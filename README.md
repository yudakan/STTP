# STTP
<h5>Sequential Two Times Pad, a strong encryption layer based on the Vernam cipher.</h5>
<p>Data is split in "chests", every chest is encrypted using a different key. Chests contais a fragment of the original data, a SHA-256 hash of that fragment and a new random key to encrypt next chest.</p>
<p>There are two keys, one to write my message and another to read his. Both client and server must know the initial keys beforehand.</p>
<p align="center">
  <img src="https://yudakan.com/imgs/sttpChest.png" />
</p>
