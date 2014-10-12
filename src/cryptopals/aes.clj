(ns cryptopals.aes
  (import javax.crypto.Cipher
          javax.crypto.spec.SecretKeySpec))


(defn aes-decrypt
  [enc-data key-data algo-string]
  (let [cipher (Cipher/getInstance algo-string)
        cipher-key (SecretKeySpec. key-data "AES")]
    (.init cipher Cipher/DECRYPT_MODE cipher-key)
    (vec (.doFinal cipher enc-data))))
       
