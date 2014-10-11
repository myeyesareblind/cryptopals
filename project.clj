(defproject cryptopals "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.apache.directory.studio/org.apache.commons.codec "1.8"]]
  :main ^:skip-aot cryptopals.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
