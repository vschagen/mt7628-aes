# Mediatek AES Crypto Engine

This AES Engine is available in the Mediatek MT76x8 SoC.

It enables hardware crypto for AES-ECB and AES-CBC with 128/192/256 keysize.

This should be added to your device DTS or better yet to the mt76x8.dtsi:

	crypto: crypto@10004000 {
		compatible = "mediatek,mtk-aes";
		reg = <0x10004000 0x1000>;

		interrupt-parent = <&intc>;
		interrupts = <13>;

		resets = <&rstctrl 29>;
		reset-names = "cryp";
		clocks = <&clkctrl 29>;
		clock-names = "cryp";
	};
