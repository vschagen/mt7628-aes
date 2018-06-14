#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <crypto/engine.h>

#include "mt7628-aes-regs.h"


static int mtk_cryp_copy_sg_src(struct mtk_cryp *cryp)
{
	int total_in;

	total_in = ALIGN(cryp->src.len, AES_BLOCK_SIZE);

	sg_copy_to_buffer(cryp->src.sg, cryp->src.nents, cryp->buf_in, cryp->src.len);

	sg_init_one(&cryp->in_sgl, cryp->buf_in, total_in);
	cryp->src.sg = &cryp->in_sgl;
	cryp->src.nents = 1;

	return 0;
}

static int mtk_cryp_copy_sg_dst(struct mtk_cryp *cryp)
{
	int total_out;
	total_out = ALIGN(cryp->dst.len, AES_BLOCK_SIZE);

	sg_init_one(&cryp->out_sgl, cryp->buf_out, total_out);
	cryp->orig_out = cryp->dst;
	cryp->dst.sg = &cryp->out_sgl;
	cryp->dst.nents = 1;

	return 0;
}

static int mtk_cryp_check_aligned(struct scatterlist *sg, size_t total,
				    size_t align)
{
	int len = 0;

	if (!total)
		return 0;

	if (!IS_ALIGNED(total, align))
		return -EINVAL;

	while (sg) {
		if (!IS_ALIGNED(sg->offset, AES_BLOCK_SIZE))
			return -EINVAL;

		if (!IS_ALIGNED(sg->length, align))
			return -EINVAL;

		len += sg->length;
		sg = sg_next(sg);
	}

	if (len != total)
		return -EINVAL;

	return 0;
}

void mtk_cryp_finish_req(struct mtk_cryp *cryp, int err)
{
	struct ablkcipher_request *req = cryp->req;

	if (cryp->sgs_copied) {
		sg_copy_from_buffer(cryp->orig_out.sg, cryp->orig_out.nents,
			cryp->buf_out, cryp->orig_out.len);
		dma_unmap_sg(cryp->dev, cryp->orig_out.sg, cryp->orig_out.nents, 				DMA_FROM_DEVICE);		
	} else {
		dma_unmap_sg(cryp->dev, cryp->dst.sg, cryp->dst.nents, DMA_FROM_DEVICE);
	}

	crypto_finalize_cipher_request(cryp->engine, req, err);

	cryp->req = NULL;
	memset(cryp->ctx->key, 0, cryp->ctx->keylen);
}

static int mtk_aes_handle_queue(struct mtk_cryp *cryp,
				 struct ablkcipher_request *req)
{
	if (req)
		return crypto_transfer_cipher_request_to_engine(cryp->engine, req);

	return 0;
}

static int mtk_cryp_prepare_cipher_req(struct crypto_engine *engine,
				struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct mtk_aes_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct mtk_cryp *cryp = ctx->cryp;
	unsigned long flags = 0;
	int ret = 0, srca = 0, dsta = 0;

	if (!cryp)
		return -ENODEV;

	/* assign new request to device */
	spin_lock_irqsave(&cryp->lock, flags);
	cryp->req = req;
	cryp->src.len = req->nbytes;
	cryp->dst.len = cryp->src.len;
	cryp->src.sg = req->src;
	cryp->dst.sg = req->dst;

	cryp->src.nents = sg_nents_for_len(cryp->src.sg, cryp->src.len);
	if (cryp->src.nents < 0) {
		dev_err(cryp->dev, "Invalid Src SG\n");
		ret = cryp->src.nents;
		goto out;
	}
	cryp->dst.nents = sg_nents_for_len(cryp->dst.sg, cryp->dst.len);
	if (cryp->dst.nents < 0) {
		dev_err(cryp->dev, "Invalid Dst SG\n");
		ret = cryp->dst.nents;
		goto out;
	}
	cryp->ctx = ctx;
	cryp->sgs_copied = 0;
	ctx->cryp = cryp;

	srca = mtk_cryp_check_aligned(cryp->src.sg, cryp->src.len, AES_BLOCK_SIZE);
	dsta = mtk_cryp_check_aligned(cryp->dst.sg, cryp->dst.len, AES_BLOCK_SIZE);

	if (srca <0 )
		ret = mtk_cryp_copy_sg_src(cryp);

	if (dsta < 0) {
		ret = mtk_cryp_copy_sg_dst(cryp);
		cryp->sgs_copied = 1;
	}

out:
	spin_unlock_irqrestore(&cryp->lock, flags);
	return ret;
}

static int mtk_cryp_cipher_one_req(struct crypto_engine *engine,
					struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct mtk_aes_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct mtk_aes_reqctx *rctx = ablkcipher_request_ctx(req);
	struct mtk_cryp *cryp = ctx->cryp;
	struct scatterlist *next_dst, *next_src;
	struct aes_txdesc *txdesc;
	struct aes_rxdesc *rxdesc;
	u32 aes_txd_info4;
	u32 aes_free_desc;
	u32 aes_tx_scatter = 0;
	u32 aes_rx_gather = 0;
	u32 i = 0, j = 0;
	unsigned int mode;
	unsigned long flags = 0;
	unsigned int mapped_ents;

	if (!cryp)
		return -ENODEV;

	spin_lock_irqsave(&cryp->lock, flags);

	mode = rctx->mode;

	if (ctx->keylen == AES_KEYSIZE_256)
		aes_txd_info4 = TX4_DMA_AES_256;
	else if (ctx->keylen == AES_KEYSIZE_192)
		aes_txd_info4 = TX4_DMA_AES_192;
	else
		aes_txd_info4 = TX4_DMA_AES_128;

	if (rctx->mode & CRYPTO_MODE_ENC)
		aes_txd_info4 |= TX4_DMA_ENC;

	if (rctx->mode & CRYPTO_MODE_CBC)
		aes_txd_info4 |= TX4_DMA_CBC | TX4_DMA_IVR;

	if (cryp->aes_tx_front_idx > cryp->aes_tx_rear_idx)
		aes_free_desc = NUM_AES_TX_DESC -
			  (cryp->aes_tx_front_idx - cryp->aes_tx_rear_idx);
	else
		aes_free_desc = cryp->aes_tx_rear_idx - cryp->aes_tx_front_idx;

	/* Map TX Descriptor */
	if (cryp->src.sg != cryp->dst.sg) {
		mapped_ents = dma_map_sg(cryp->dev, cryp->src.sg, cryp->src.nents,
				DMA_TO_DEVICE);
	} else {
		mapped_ents = dma_map_sg(cryp->dev, cryp->src.sg, cryp->src.nents,
				DMA_BIDIRECTIONAL);
	}
	if (mapped_ents > aes_free_desc) {
		spin_unlock_irqrestore(&cryp->lock, flags);
		return -EAGAIN;
	}

	for_each_sg(cryp->src.sg, next_src, mapped_ents, i) {
		aes_tx_scatter = (cryp->aes_tx_rear_idx + i + 1) % NUM_AES_TX_DESC;
		txdesc = &cryp->tx[aes_tx_scatter];

		if ((rctx->mode & CRYPTO_MODE_CBC) && (i == 0)) {
			if (!rctx->iv)
				memset((void *)txdesc->IV, 0xFF, sizeof(uint32_t)*4);
			else
				memcpy((void *)txdesc->IV, rctx->iv, sizeof(uint32_t)*4);

			txdesc->txd_info4 = aes_txd_info4 | TX4_DMA_KIU;
		} else {
			txdesc->txd_info4 = aes_txd_info4;
		}

		if (i == 0) {
			txdesc->SDP0 = ctx->phy_key;
			txdesc->txd_info2 = TX2_DMA_SDL0_SET(ctx->keylen);
		} else {
			txdesc->txd_info2 = 0;
		}
		txdesc->SDP1 = (u32)sg_dma_address(next_src);
		txdesc->txd_info2 |= TX2_DMA_SDL1_SET(sg_dma_len(next_src));
		}
		txdesc->txd_info2 |= TX2_DMA_LS1;

	dma_unmap_sg(cryp->dev, cryp->src.sg, cryp->src.nents, DMA_TO_DEVICE);

	/* Map RX Descriptor */
	if (cryp->aes_rx_front_idx > cryp->aes_rx_rear_idx)
		aes_free_desc = NUM_AES_RX_DESC - (cryp->aes_rx_front_idx -
							cryp->aes_rx_rear_idx);
	else
		aes_free_desc = cryp->aes_rx_rear_idx - cryp->aes_rx_front_idx;

	if (cryp->src.sg != cryp->dst.sg) {
		mapped_ents = dma_map_sg(cryp->dev, cryp->dst.sg, cryp->dst.nents,
				DMA_FROM_DEVICE);
	}

	if (mapped_ents > aes_free_desc) {
		spin_unlock_irqrestore(&cryp->lock, flags);
		return -EAGAIN;
	}

	for_each_sg(cryp->dst.sg, next_dst, mapped_ents, j) {
		aes_rx_gather = (cryp->aes_rx_rear_idx + j + 1) % NUM_AES_RX_DESC;
		rxdesc = &cryp->rx[aes_rx_gather];
		rxdesc->SDP0 = sg_dma_address(next_dst);
		rxdesc->rxd_info2 = RX2_DMA_SDL0_SET(sg_dma_len(next_dst));
		}
		rxdesc->rxd_info2 |= RX2_DMA_LS0;

	cryp->aes_tx_rear_idx = aes_tx_scatter;
	cryp->aes_rx_rear_idx = aes_rx_gather;	

	/*
	 * Make sure all data is updated before starting engine.
	 */
	wmb();
	/* Writing new scattercount starts PDMA action */
	aes_tx_scatter = (aes_tx_scatter + 1) % NUM_AES_TX_DESC;
	iowrite32(aes_tx_scatter, cryp->base + AES_TX_CTX_IDX0);
	spin_unlock_irqrestore(&cryp->lock, flags);

	return 0;
}

static struct mtk_cryp *mtk_aes_find_dev(struct mtk_aes_ctx *ctx)
{
	struct mtk_cryp *cryp = NULL;
	struct mtk_cryp *tmp;

	spin_lock_bh(&mtk_aes.lock);
	if (!ctx->cryp) {
		list_for_each_entry(tmp, &mtk_aes.dev_list, aes_list) {
			cryp = tmp;
			break;
		}
		ctx->cryp = cryp;
	} else {
		cryp = ctx->cryp;
	}
	spin_unlock_bh(&mtk_aes.lock);

	return cryp;
}

static int mtk_aes_crypt(struct ablkcipher_request *req, unsigned int mode)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct mtk_aes_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct mtk_aes_reqctx *rctx = ablkcipher_request_ctx(req);
	struct mtk_cryp *cryp;
	int ret;

	if (req->nbytes < NUM_AES_BYPASS) {
		SKCIPHER_REQUEST_ON_STACK(subreq, ctx->fallback);

		skcipher_request_set_tfm(subreq, ctx->fallback);
		skcipher_request_set_callback(subreq, req->base.flags, NULL,
					      NULL);
		skcipher_request_set_crypt(subreq, req->src, req->dst,
					   req->nbytes, req->info);

		if (mode & CRYPTO_MODE_ENC)
			ret = crypto_skcipher_encrypt(subreq);
		else
			ret = crypto_skcipher_decrypt(subreq);

		skcipher_request_zero(subreq);
		return ret;
	}

	cryp = mtk_aes_find_dev(ctx);

	if (!cryp)
		return -ENODEV;

	rctx->mode = mode;
	rctx->iv  = req->info;
	rctx->count = cryp->aes_tx_rear_idx;
	
	return mtk_aes_handle_queue(cryp, req);
}

/* ********************** ALG API ************************************ */

static int mtk_aes_setkey(struct crypto_ablkcipher *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct mtk_aes_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	int ret;

	if (keylen != AES_KEYSIZE_128 &&
	    keylen != AES_KEYSIZE_192 &&
	    keylen != AES_KEYSIZE_256) {
		crypto_ablkcipher_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
		}

	if (ctx->phy_key) 
		dma_unmap_single(NULL, ctx->phy_key, ctx->keylen,
			 DMA_TO_DEVICE);

	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;

	ctx->phy_key = dma_map_single(NULL, ctx->key, ctx->keylen,
			 DMA_TO_DEVICE);

	crypto_skcipher_clear_flags(ctx->fallback, CRYPTO_TFM_REQ_MASK);
	crypto_skcipher_set_flags(ctx->fallback, tfm->base.crt_flags &
						 CRYPTO_TFM_REQ_MASK);

	ret = crypto_skcipher_setkey(ctx->fallback, key, keylen);

	return 0;
}

static int mtk_aes_ecb_encrypt(struct ablkcipher_request *req)
{
	return mtk_aes_crypt(req, CRYPTO_MODE_ENC);
}

static int mtk_aes_ecb_decrypt(struct ablkcipher_request *req)
{
	return mtk_aes_crypt(req, 0);
}

static int mtk_aes_cbc_encrypt(struct ablkcipher_request *req)
{
	return mtk_aes_crypt(req, CRYPTO_MODE_ENC | CRYPTO_MODE_CBC);
}

static int mtk_aes_cbc_decrypt(struct ablkcipher_request *req)
{
	return mtk_aes_crypt(req, CRYPTO_MODE_CBC);
}

static int mtk_aes_cra_init(struct crypto_tfm *tfm)
{
	const char *name = crypto_tfm_alg_name(tfm);
	const u32 flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK;
	struct mtk_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_skcipher *blk;

	blk = crypto_alloc_skcipher(name, 0, flags);

	if (IS_ERR(blk))
		return PTR_ERR(blk);

	ctx->fallback = blk;

	tfm->crt_ablkcipher.reqsize = sizeof(struct mtk_aes_reqctx);

	return 0;
}

static void mtk_aes_cra_exit(struct crypto_tfm *tfm)
{
	struct mtk_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	if (ctx->fallback)
		crypto_free_skcipher(ctx->fallback);

	ctx->fallback = NULL;
}

/* ********************** ALGS ************************************ */

static struct crypto_alg aes_algs[] = {
{
	.cra_name		= "cbc(aes)",
	.cra_driver_name	= "cbc-aes-mt7628",
	.cra_priority		= 300,
	.cra_flags		= CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK |
				  CRYPTO_ALG_TYPE_ABLKCIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct mtk_aes_ctx),
	.cra_alignmask		= 0xf,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= mtk_aes_cra_init,
	.cra_exit		= mtk_aes_cra_exit,
	.cra_u.ablkcipher = {
		.setkey		= mtk_aes_setkey,
		.encrypt	= mtk_aes_cbc_encrypt,
		.decrypt	= mtk_aes_cbc_decrypt,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		}
},
{
	.cra_name		= "ecb(aes)",
	.cra_driver_name	= "ecb-aes-mt7628",
	.cra_priority		= 300,
	.cra_flags		= CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK |
				  CRYPTO_ALG_TYPE_ABLKCIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct mtk_aes_ctx),
	.cra_alignmask		= 0xf,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= mtk_aes_cra_init,
	.cra_exit		= mtk_aes_cra_exit,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_u.ablkcipher = {
		.setkey		= mtk_aes_setkey,
		.encrypt	= mtk_aes_ecb_encrypt,
		.decrypt	= mtk_aes_ecb_decrypt,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
		}
},
};

int mtk_cipher_alg_register(struct mtk_cryp *cryp)
{
	int err, i;

	INIT_LIST_HEAD(&cryp->aes_list);
	spin_lock_init(&cryp->lock);
	spin_lock(&mtk_aes.lock);
	list_add_tail(&cryp->aes_list, &mtk_aes.dev_list);
	spin_unlock(&mtk_aes.lock);

	for (i = 0; i < ARRAY_SIZE(aes_algs); i++) {
		dev_info(cryp->dev, "Register: %s\n", aes_algs[i].cra_name);
		err = crypto_register_alg(&aes_algs[i]);
		if (err)
			goto err_aes_algs;
	}

	cryp->engine->prepare_cipher_request = mtk_cryp_prepare_cipher_req;
	cryp->engine->cipher_one_request = mtk_cryp_cipher_one_req;

	err = crypto_engine_start(cryp->engine);
	if (err) {
		dev_err(cryp->dev, "Could not start crypto engine\n");
		goto err_engine2;
	}

	return 0;

err_aes_algs:
	for (; i--; )
		crypto_unregister_alg(&aes_algs[i]);

	return err;
err_engine2:
	crypto_engine_exit(cryp->engine);
	return err;
}

void mtk_cipher_alg_release(struct mtk_cryp *cryp)
{
	int i;

	spin_lock(&mtk_aes.lock);
	list_del(&cryp->aes_list);
	spin_unlock(&mtk_aes.lock);

	for (i = 0; i < ARRAY_SIZE(aes_algs); i++)
		crypto_unregister_alg(&aes_algs[i]);
}


