(ns cryptopals.aes
  (use [cryptopals.vecutils]
       [cryptopals.sequtils])
  (import javax.crypto.Cipher
          javax.crypto.spec.SecretKeySpec))

(def key-length
  16)

(defn aes-crypto-cbc-encrypt
  [data iv key]
  (let [cipher (Cipher/getInstance "AES/ECB/PKCS5Padding")
        cipher-key (SecretKeySpec. (byte-array key) "AES")]
    (.init cipher Cipher/ENCRYPT_MODE cipher-key)
    (loop [data (partition-all key-length data)
           r [(byte-array iv)]]
      (if (empty? data)
        (flatten (rest (for [bytear r]
                         (vec bytear))))
        (recur (rest data) 
               (conj r 
                     (.update cipher 
                              (bytear-xor-bytear (byte-array 
                                                  (PKCS7-pad (first data) key-length))
                                                 (last r)))))))))

(defn aes-crypto-cbc-decrypt
  [data iv key]
  (let [cipher (Cipher/getInstance "AES/ECB/NoPadding")
        cipher-key (SecretKeySpec. (byte-array key) "AES")]
    (.init cipher Cipher/DECRYPT_MODE cipher-key)
    (loop [data (partition-all key-length data)
           xor (byte-array iv)
           r []]
      (if (empty? data)
        (flatten (for [bytear r]
                   (vec bytear)))
        (recur (rest data)
               (byte-array (first data))
               (conj r (bytear-xor-bytear xor (.update cipher (byte-array (PKCS7-pad (first data) key-length))))))))))

(defn aes-decrypt-do-final
  [enc-data key-data algo-string]
  (let [cipher (Cipher/getInstance algo-string)
        cipher-key (SecretKeySpec. key-data "AES")]
    (.init cipher Cipher/DECRYPT_MODE cipher-key)
    (vec (.doFinal cipher enc-data))))

