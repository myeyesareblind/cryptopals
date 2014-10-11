(ns cryptopals.vecutils)

(defn vec-xor-vec 
  [x y]
  (vec (let [nx (count x)
             ny (count y)]
         (for [i (range (max nx ny))]
           (bit-xor
            (get x (rem i nx))
            (get y (rem i ny)))))))

(defn ham-dist
  ([x y] 
     (if (coll? x)
       (/ (apply + (map ham-dist x y)) (count x) 1.0)
       (ham-dist (bit-xor x y))))
  ([b]
  (loop [i 7
         r 0]
    (if (= -1 i)
      r
      (recur (dec i) (+ r (if (bit-test b i) 1 0)))))))

(defn vec-hamm-dist 
  [x y]
  (apply + (map ham-dist (map bit-xor x y))))

(defn count-aprox-hamm-dist
  [x lenk]
  (let [part (take 10 (partition lenk x))]
    (loop [part part
           r 0]
      (if (empty? part)
        r
        (recur (rest (rest part)) (ham-dist (first part) (second part)))))))

(defn split-vec
  [vec klen]
  (let [r (for [i (range klen)]
            [])
        vec-len (count vec)]
    (doseq [v vec i (range vec-len)]
      (conj (get r (rem i klen)) v))
    r))
      
      