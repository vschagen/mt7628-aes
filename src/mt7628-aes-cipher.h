/* MT7628 AES Cipher Header */


int mtk_cipher_alg_register(struct mtk_cryp *cryp);

void mtk_cipher_alg_release(struct mtk_cryp *cryp);

void mtk_cryp_finish_req(struct mtk_cryp *cryp, int ret);
