#include <linux/module.h>
#include <linux/version.h>
#include <linux/clk.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <crypto/engine.h>

#include "mt7628-aes-regs.h"
#include "mt7628-aes-cipher.h"

static void aes_engine_start(struct mtk_cryp *cryp)
{
	u32 regVal;

	u32 AES_glo_cfg = AES_TX_DMA_EN | AES_RX_DMA_EN | AES_TX_WB_DDONE
			| AES_DESC_5DW_INFO_EN | AES_RX_ANYBYTE_ALIGN
			| AES_32_BYTES | AES_RX_2B_OFFSET;

	writel(AES_DLY_INIT_VALUE, cryp->base + AES_DLY_INT_CFG);
	writel(AES_MASK_INT_ALL, cryp->base + AES_INT_STATUS);
	regVal = readl(cryp->base + AES_INT_STATUS);
	writel(AES_MASK_INT_ALL, cryp->base + AES_INT_MASK);

	AES_glo_cfg |= AES_BT_SIZE_32DWORDS;
	writel(AES_glo_cfg, cryp->base + AES_GLO_CFG);
}

static void aes_engine_reset(void)
{
	u32 val;

	val = readl(REG_CLKCTRL);
	val |= RALINK_CRYPTO_CLK_EN;
	iowrite32(val, REG_CLKCTRL);

	udelay(10);

	val = readl(REG_RSTCTRL);
	val |= RALINK_CRYPTO_RST;
	iowrite32(val, REG_RSTCTRL);

	udelay(10);

	val &= ~(RALINK_CRYPTO_RST);
	iowrite32(val, REG_RSTCTRL);

	udelay(100);
}

static void aes_engine_stop(struct mtk_cryp *cryp)
{
	int i;
	u32 regVal;

	regVal = readl(cryp->base + AES_GLO_CFG);
	regVal &= ~(AES_TX_WB_DDONE | AES_RX_DMA_EN | AES_TX_DMA_EN);
	iowrite32(regVal, cryp->base + AES_GLO_CFG);

	/* wait AES stopped */
	for (i = 0; i < 50; i++) {
		msleep(1);
		regVal = readl(cryp->base + AES_GLO_CFG);
		if (!(regVal & (AES_RX_DMA_BUSY | AES_TX_DMA_BUSY)))
			break;
	}

	/* disable AES interrupt */
	iowrite32(0, cryp->base + AES_INT_MASK);
}

static irqreturn_t mtk_cryp_irq(int irq, void *arg)
{
	struct mtk_cryp *cryp = arg;
	//struct ablkcipher_request *req = cryp->req;
	//struct mtk_aes_reqctx *rctx = ablkcipher_request_ctx(req);
	struct aes_txdesc *txdesc;
	struct aes_rxdesc *rxdesc;
	u32 k, m, regVal;
	int try_count = 0;
	int ret = 0;
	unsigned long flags = 0;

	spin_lock_irqsave(&cryp->lock, flags);
	/* disable AES interrupt */
	writel(0, cryp->base + AES_INT_MASK);

	do {
		regVal = readl(cryp->base + AES_GLO_CFG);
		if ((regVal & (AES_RX_DMA_EN | AES_TX_DMA_EN)) 
			!= (AES_RX_DMA_EN | AES_TX_DMA_EN)) {
			dev_err(cryp->dev, "No active DMA on interrupt!");
			spin_unlock_irqrestore(&cryp->lock, flags);
			return -EIO;
		}
		if (!(regVal & (AES_RX_DMA_BUSY | AES_TX_DMA_BUSY)))
			break;
		try_count++;
		dev_info(cryp->dev, "DMA busy: %d", try_count);
		cpu_relax();
	} while (1);

	k = cryp->aes_rx_front_idx;
	m = cryp->aes_tx_front_idx;
	try_count = 0;

	do {
		rxdesc = &cryp->rx[k];

		if (!(rxdesc->rxd_info2 & RX2_DMA_DONE)) {
			try_count++;
			dev_info(cryp->dev, "Try count: %d", try_count);
			cpu_relax();
			continue;
		}
		rxdesc->rxd_info2 &= ~RX2_DMA_DONE;

		if (rxdesc->rxd_info2 & RX2_DMA_LS0) {
			/* last RX, release correspond TX */
			do {
				txdesc = &cryp->tx[m];
				/*
				if (!(txdesc->txd_info2 & TX2_DMA_DONE))
					break;
				*/
				if (txdesc->txd_info2 & TX2_DMA_LS1)
					break;
				m = (m + 1) % NUM_AES_TX_DESC;
			} while (1);

			if (m == cryp->aes_tx_rear_idx) {
				dev_dbg(cryp->dev, "Tx Desc[%d] Clean\n",
					cryp->aes_tx_rear_idx);
			}
			cryp->aes_rx_front_idx = (k + 1) % NUM_AES_RX_DESC;

			if (k == cryp->aes_rx_rear_idx) {
				dev_dbg(cryp->dev, "Rx Desc[%d] Clean\n",
					cryp->aes_rx_rear_idx);
				break;
			}
		}
		k = (k+1) % NUM_AES_RX_DESC;
	} while (1);

	cryp->aes_rx_rear_idx = k;
	cryp->aes_tx_front_idx = (m + 1) % NUM_AES_TX_DESC;

	iowrite32(k, cryp->base + AES_RX_CALC_IDX0);

	mtk_cryp_finish_req(cryp, ret);

	/* enable interrupt */
	iowrite32(AES_MASK_INT_ALL, cryp->base + AES_INT_MASK);
	iowrite32(AES_MASK_INT_ALL, cryp->base + AES_INT_STATUS);
	/* flush write */
	regVal=ioread32(cryp->base + AES_INT_STATUS);

	spin_unlock_irqrestore(&cryp->lock, flags);

	return IRQ_HANDLED;
}

/* Allocate Descriptor rings */
static int aes_engine_desc_init(struct mtk_cryp *cryp)
{
	int i;
	u32 regVal;
	size_t size;

	size = (NUM_AES_TX_DESC * sizeof(struct aes_txdesc));

	cryp->tx = dma_zalloc_coherent(cryp->dev, size,
					&cryp->phy_tx, GFP_KERNEL);
	if (!cryp->tx)
		goto err_cleanup;

	dev_info(cryp->dev, "TX Ring : %08X\n", cryp->phy_tx);

	size = NUM_AES_RX_DESC * sizeof(struct aes_rxdesc);

	cryp->rx = dma_zalloc_coherent(cryp->dev, size,
					&cryp->phy_rx, GFP_KERNEL);
	if (!cryp->rx)
		goto err_cleanup;

	dev_info(cryp->dev, "RX Ring : %08X\n", cryp->phy_rx);

	cryp->buf_in = (void *)__get_free_pages(GFP_ATOMIC, 4);
	cryp->buf_out = (void *)__get_free_pages(GFP_ATOMIC, 4);
	if (!cryp->buf_in || !cryp->buf_out) {
		dev_err(cryp->dev, "Can't allocate pages when unaligned\n");
		goto err_cleanup;
	}
	for (i = 0; i < NUM_AES_TX_DESC; i++)
		cryp->tx[i].txd_info2 |= TX2_DMA_DONE;

	cryp->aes_tx_front_idx = 0;
	cryp->aes_tx_rear_idx = NUM_AES_TX_DESC-1;

	cryp->aes_rx_front_idx = 0;
	cryp->aes_rx_rear_idx = NUM_AES_RX_DESC-1;

	regVal = readl(cryp->base + AES_GLO_CFG);
	regVal &= 0x00000ff0;
	iowrite32(regVal, cryp->base + AES_GLO_CFG);
	regVal = readl(cryp->base + AES_GLO_CFG);

	iowrite32((u32)cryp->phy_tx, cryp->base + AES_TX_BASE_PTR0);
	iowrite32((u32)NUM_AES_TX_DESC, cryp->base + AES_TX_MAX_CNT0);
	iowrite32(0, cryp->base + AES_TX_CTX_IDX0);
	iowrite32(AES_PST_DTX_IDX0, cryp->base + AES_RST_CFG);

	iowrite32((u32)cryp->phy_rx, cryp->base + AES_RX_BASE_PTR0);
	iowrite32((u32)NUM_AES_RX_DESC, cryp->base + AES_RX_MAX_CNT0);
	iowrite32((u32)(NUM_AES_RX_DESC - 1), cryp->base + AES_RX_CALC_IDX0);
	regVal = readl(cryp->base + AES_RX_CALC_IDX0);
	iowrite32(AES_PST_DRX_IDX0, cryp->base + AES_RST_CFG);

	return 0;
err_cleanup:
	return -ENOMEM;
}

/* Free Descriptor Rings */
static void aes_engine_desc_free(struct mtk_cryp *cryp)
{
	size_t	size;

	iowrite32(0, cryp->base + AES_TX_BASE_PTR0);
	iowrite32(0, cryp->base + AES_RX_BASE_PTR0);

	size = NUM_AES_TX_DESC * sizeof(struct aes_txdesc);

	if (cryp->tx) {
		dma_free_coherent(cryp->dev, size, cryp->tx, cryp->phy_tx);
		cryp->tx = NULL;
		cryp->phy_tx = 0;
	}

	size = NUM_AES_TX_DESC * sizeof(struct aes_rxdesc);

	if (cryp->rx) {
		dma_free_coherent(cryp->dev, size, cryp->rx, cryp->phy_rx);
		cryp->rx = NULL;
		cryp->phy_rx = 0;
	}

	free_pages((unsigned long)cryp->buf_in, 4);
	free_pages((unsigned long)cryp->buf_out, 4);
}

/* Probe using Device Tree; needs helper to force loading on earlier DTS firmware */

static int mt7628_cryp_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mtk_cryp *cryp;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	int ret;

	cryp = devm_kzalloc(dev, sizeof(*cryp), GFP_KERNEL);
	if (!cryp)
		return -ENOMEM;

	cryp->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(cryp->base))
		return PTR_ERR(cryp->base);

	cryp->dev = dev;

	aes_engine_reset(); // force reset and clk enable

	dev_info(dev, "HW verson: %02X\n", readl(cryp->base + AES_INFO) >> 28);

	cryp->irq = platform_get_irq(pdev, 0);
	if (cryp->irq < 0) {
		dev_err(dev, "Cannot get IRQ resource\n");
		return cryp->irq;
	}

	ret = devm_request_threaded_irq(cryp->dev, cryp->irq, mtk_cryp_irq,
					NULL, IRQF_ONESHOT,
					dev_name(cryp->dev), cryp);

	if (ret) {
		dev_err(cryp->dev, "Cannot grab IRQ\n");
		return ret;
	}
	dev_info(cryp->dev, "IRQ %d assigned to handler", cryp->irq);

	/* Hardcoded Clk at the moment
	cryp->clk = devm_clk_get(dev, "crypto");
			if (IS_ERR(cryp->clk)) {
				cryp->clk = NULL;
				dev_err(dev, "Could not find clock\n");
			}
	*/
	cryp->clk = NULL;
	/* Initialize crypto engine */
	cryp->engine = crypto_engine_alloc_init(dev, 0);
	if (!cryp->engine) {
		dev_err(dev, "Could not init crypto engine\n");
		ret = -ENOMEM;
		goto err_engine1;
	}

	/* Allocate descriptor rings */

	ret = aes_engine_desc_init(cryp);

	/* Register Ciphers */

	ret = mtk_cipher_alg_register(cryp);

	aes_engine_start(cryp); // Start hw engine

	platform_set_drvdata(pdev, cryp);

	dev_info(dev, "Initialized.\n");

	return 0;

err_engine1:

	return ret;
}

static int __exit mt7628_cryp_remove(struct platform_device *pdev)
{
	struct mtk_cryp *cryp = platform_get_drvdata(pdev);

	if (!cryp) {
		printk("Remove: no crypto device found");
		return -ENODEV;
	}
	crypto_engine_exit(cryp->engine);
	aes_engine_stop(cryp);
	mtk_cipher_alg_release(cryp);
	aes_engine_desc_free(cryp);
	dev_info(cryp->dev, "Unloaded.\n");
	platform_set_drvdata(pdev, NULL);

	return 0;
}

static const struct of_device_id of_crypto_id[] = {
	{ .compatible = "mediatek,mtk-aes" },
	{},
};

MODULE_DEVICE_TABLE(of, of_crypto_id);

static struct platform_driver mt7628_cryp_driver = {
	.probe  = mt7628_cryp_probe,
	.remove = mt7628_cryp_remove,
	.driver = {
		.name           = "mt7628-aes",
		.of_match_table = of_crypto_id,
	},
};

module_platform_driver(mt7628_cryp_driver);

MODULE_AUTHOR("Richard van Schagen <vschagen@cs.com>");
MODULE_DESCRIPTION("MT7628 AES Crypto hardware driver");
MODULE_LICENSE("GPL");


