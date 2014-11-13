(ns cryptopals.aes
  (use [cryptopals.vecutils]
       [cryptopals.intutils]
       [cryptopals.sequtils])
  (import javax.crypto.Cipher
          javax.crypto.spec.SecretKeySpec
          javax.crypto.spec.IvParameterSpec))

(def key-length
  16)

(defn aes-ecb-encrypt
  [enc-data key-data]
  (let [cipher (Cipher/getInstance "AES/ECB/PKCS5Padding")
        cipher-key (SecretKeySpec. (byte-array key-data) "AES")]
    (.init cipher Cipher/ENCRYPT_MODE cipher-key)
    (vec (.doFinal cipher (byte-array enc-data)))))

(defn aes-ecb-decrypt
  [enc-data key-data]
  (let [cipher (Cipher/getInstance "AES/ECB/PKCS5Padding")
        cipher-key (SecretKeySpec. (byte-array key-data) "AES")]
    (.init cipher Cipher/DECRYPT_MODE cipher-key)
    (vec (.doFinal cipher (byte-array enc-data)))))

(defn aes-cbc-encrypt
  [enc-data key-data iv]
  (let [cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")
        cipher-key (SecretKeySpec. (byte-array key-data) "AES")]
    (.init cipher Cipher/ENCRYPT_MODE cipher-key (IvParameterSpec. (byte-array iv)))
    (vec (.doFinal cipher (byte-array enc-data)))))

(defn aes-cbc-decrypt
  [enc-data key-data iv]
  (let [cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")
        cipher-key (SecretKeySpec. (byte-array key-data) "AES")]
    (.init cipher Cipher/DECRYPT_MODE cipher-key (IvParameterSpec. (byte-array iv)))
    (vec (.doFinal cipher (byte-array enc-data)))))

(defn ctr-stream-bytes
  [nonce i]
  (concat nonce (int64-to-little-end-byte-array i)))

(defn aes-ctr-crypt
  [data key-data nonce]
  (let [cipher (Cipher/getInstance "AES/ECB/NoPadding")
        cipher-key (SecretKeySpec. (byte-array key-data) "AES")]
    (.init cipher Cipher/ENCRYPT_MODE cipher-key)
    (flatten (let [list-data (partition-all 16 data)]
      (map (fn [x i]
             (vec-xor-vec x (.update cipher (byte-array (ctr-stream-bytes nonce i)))))
           list-data 
           (range (count list-data)))))))

  (defn aes-random-encrypt
    [data]
    (let [data (flatten (conj (random-byte-list (rand-int 10))
                              data
                              (random-byte-list (rand-int 10))))
          key (random-byte-list key-length)
          iv (random-byte-list key-length)]
      (if (zero? (rand-int 2))
        (aes-cbc-encrypt data iv key)
        (aes-ecb-encrypt data key))))
