# Mediatek AES Crypto Engine

New and improved AES Crypto Engine. Written from scratch to enable full features and performance
on Linux Kernel v4.6+. It features full asynchronous support with crypto-engine queue handling.

Added alignment checks and buffer copy in order to work with OpenVPN. This comes with 
performance penalties. 

This AES Engine is available in the Mediatek MT7628 and MT7688 SoC

Possibly the RT6856 is using the engine. The Datasheet specifies AES Engine like the MT7628.
Media releases about the Ralink RT6856 state it as IPSec accelerator.

For now (since its target is MT76x8) only Little Endian supported.
