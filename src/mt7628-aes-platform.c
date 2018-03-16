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

static void aes_engine_reset(void)
{
	u32 val;

	val = sysRegRead(REG_CLKCTRL);
	val |= RALINK_CRYPTO_CLK_EN;
	sysRegWrite(REG_CLKCTRL, val);

	udelay(10);

	val = sysRegRead(REG_RSTCTRL);
	val |= RALINK_CRYPTO_RST;
	sysRegWrite(REG_RSTCTRL, val);

	udelay(10);

	val &= ~(RALINK_CRYPTO_RST);
	sysRegWrite(REG_RSTCTRL, val);

	udelay(100);
}

static void aes_engine_stop(void)
{
	int i;
	u32 regValue;

	regValue = sysRegRead(AES_GLO_CFG);
	regValue &= ~(AES_TX_WB_DDONE | AES_RX_DMA_EN | AES_TX_DMA_EN);
	sysRegWrite(AES_GLO_CFG, regValue);

	/* wait AES stopped */
	for (i = 0; i < 50; i++) {
		msleep(1);
		regValue = sysRegRead(AES_GLO_CFG);
		if (!(regValue & (AES_RX_DMA_BUSY | AES_TX_DMA_BUSY)))
			break;
	}

	/* disable AES interrupt */
	sysRegWrite(AES_INT_MASK, 0);
}

static void aes_engine_start(void)
{
	u32 AES_glo_cfg = AES_TX_DMA_EN | AES_RX_DMA_EN | AES_TX_WB_DDONE | AES_DESC_5DW_INFO_EN | AES_RX_ANYBYTE_ALIGN;

	sysRegWrite(AES_DLY_INT_CFG, AES_DLY_INIT_VALUE);
	sysRegWrite(AES_INT_STATUS, 0xffffffff);
	sysRegWrite(AES_INT_MASK, AES_MASK_INT_ALL);

	AES_glo_cfg |= AES_BT_SIZE_16DWORDS;
	sysRegWrite(AES_GLO_CFG, AES_glo_cfg);
}


/* Allocate Descriptor rings */
static int aes_engine_desc_init(struct mtk_cryp *cryp)
{
	int i;
	u32 regVal;
	size_t size;

	size = (NUM_AES_TX_DESC * sizeof(struct AES_txdesc));

	cryp->tx = dma_zalloc_coherent(cryp->dev, size, &cryp->phy_tx, GFP_KERNEL);
	if (!cryp->tx)
		goto err_cleanup;

	dev_info(cryp->dev, "TX Ring : %08X \n", cryp->phy_tx);
	

	size = NUM_AES_RX_DESC * sizeof(struct AES_rxdesc);

	cryp->rx = dma_zalloc_coherent(cryp->dev, size, &cryp->phy_rx, GFP_KERNEL);
	if (!cryp->rx)
		goto err_cleanup;

	dev_info(cryp->dev, "RX Ring : %08X \n", cryp->phy_rx);

	for (i = 0; i < NUM_AES_TX_DESC; i++) {
		cryp->tx[i].txd_info2 |= TX2_DMA_DONE;
	}

	cryp->aes_tx_front_idx = 0;
	cryp->aes_tx_rear_idx = NUM_AES_TX_DESC-1;

	cryp->aes_rx_front_idx = 0;
	cryp->aes_rx_rear_idx = NUM_AES_RX_DESC-1;

	wmb();

	regVal = sysRegRead(AES_GLO_CFG);
	regVal &= 0x00000ff0;
	sysRegWrite(AES_GLO_CFG, regVal);
	regVal = sysRegRead(AES_GLO_CFG);

	sysRegWrite(AES_TX_BASE_PTR0, phys_to_bus((u32)cryp->phy_tx));
	sysRegWrite(AES_TX_MAX_CNT0, cpu_to_le32((u32)NUM_AES_TX_DESC));
	sysRegWrite(AES_TX_CTX_IDX0, 0);
	sysRegWrite(AES_RST_CFG, AES_PST_DTX_IDX0);

	sysRegWrite(AES_RX_BASE_PTR0, phys_to_bus((u32)cryp->phy_rx));
	sysRegWrite(AES_RX_MAX_CNT0, cpu_to_le32((u32)NUM_AES_RX_DESC));
	sysRegWrite(AES_RX_CALC_IDX0, cpu_to_le32((u32)(NUM_AES_RX_DESC - 1)));
	regVal = sysRegRead(AES_RX_CALC_IDX0);
	sysRegWrite(AES_RST_CFG, AES_PST_DRX_IDX0);

	return 0;

err_cleanup:
	return -ENOMEM;
}

/* Free Descriptor Rings */
static void aes_engine_desc_free(struct mtk_cryp *cryp)
{
	size_t	size;

	sysRegWrite(AES_TX_BASE_PTR0, 0);
	sysRegWrite(AES_RX_BASE_PTR0, 0);

	size = NUM_AES_TX_DESC * sizeof(struct AES_txdesc);

	if (cryp->tx) {
		dma_free_coherent(cryp->dev, size , cryp->tx, cryp->phy_tx);
		cryp->tx = NULL;
		cryp->phy_tx = 0;
	}

	size = NUM_AES_TX_DESC * sizeof(struct AES_txdesc);

	if (cryp->rx) {
		dma_free_coherent(cryp->dev, size, cryp->rx, cryp->phy_rx);
		cryp->rx = NULL;
		cryp->phy_rx = 0;
	}

	return;
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

	cryp->dev=dev;

	aes_engine_reset(); // force reset and clk enable

	dev_info(dev, "HW verson: %02X\n", sysRegRead(AES_INFO) >> 28);
	
	cryp->irq = platform_get_irq(pdev, 0);
	if (cryp->irq < 0) {
		dev_err(dev, "Cannot get IRQ resource\n");
		return cryp->irq;
	}

	cryp->clk = devm_clk_get(dev, "crypto");
			if (IS_ERR(cryp->clk)) {
				cryp->clk = NULL;
				dev_err(dev, "Could not find clock\n");
			}

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

	aes_engine_start(); // Start hw engine	

	platform_set_drvdata(pdev, cryp);

	dev_info(dev, "Initialized\n");

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
	aes_engine_stop();
	aes_engine_desc_free(cryp);

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


