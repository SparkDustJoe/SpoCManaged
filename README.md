# SpoCManaged
A C# Port (.Net Core 3) of the SpoC AEAD lightweight crypto scheme.

NIST Lightweight Cryptography Project: https://csrc.nist.gov/Projects/lightweight-cryptography/  
Source: https://uwaterloo.ca/communications-security-lab/lwc/spoc  

Riham AlTawy  
Guang Gong  
Morgan He  
Ashwin Jha  
Kalikinkar Mandal  
Mridul Nandi  
Raghvendra Rohit  
Dustin Sparks (*this port only*, taken directly from the reference implementation provided to NIST)

From the authors: *"SpoC (pronounced as Spock) stands for Sponge with masked Capacity, is an authenticated encryption with associated data. It is a joint collaboration between the Communication Security (ComSec) laboratory of the University of Waterloo and the Indian Statistical Institute (ISI). SpoC is designed by Riham AlTawy, Guang Gong, Morgan He, Ashwin Jha, Kalikinkar Mandal, Mridul Nandi, and Raghvendra Rohit. The mode of operation adopted in SpoC provides higher security guarantees, thus relaxing the constraints on the state size of the underlying permutation. SpoC provides 128-bit security using 192-bit permutation which is further built using two of the most efficient and well cryptanalyzed constructions, namely, Generalized Feistel Structure (GFS) Type II and the Simeck/Simon round function."*
