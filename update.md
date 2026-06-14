dobra, widzę że wszyscy są pytani o updatey, więc moja kolej

Ogólnie przez to że przez ostatnie 4 dni uczyłem się/pisałem egzaminy to niewiele zrobiłem w tym czasie

Tutaj jest "checklista" rzeczy które chciałem zrobić przez cały ten czas:
    * Własny wrapper do HIDL/Keymaster
    * Własny wrapper do AIDL/Keymint
    * Narzędzia do odszyfrowywania kluczy CE, uwierzytelnianie przez Gatekeeper/Weaver

Znaaaczną większość czasu zajęło mi zrobienie komunikacji z HALami przez HIDL/AIDL przy pomocy bindera, oraz zrobienie wrapperów do różnych wersjie inteerfejsów Keymaster i KeyMint.
Z racji braku dokumentacji oraz tego że jedna zmiana w moich bibliotekach oznacza tysiące linijek kodu do migracji, proces ten był strasznie czasochłonny i w sumie nie dziwię się czemu nikomu innemu nie chciało się tego robić

Ale w sumie w końcu  udało mi się zrobić (przez cały okres praktyk):
    * Zreimplementowanie całego stacku HIDL - libhwbinder, android.hardware.keymaster@* i innych kawałków komponentów systemowych:
        * Kod interfejsujący ze sterownikiem binder (libhwbinder)
        * Ser/Des Parceli HIDL (libhwbinder)
        * Ser/Des typów HIDL (prymitywne, hidl_string, hidl_vec)
        * Ser/Des typów Keymaster (te automatycznie wygenerowane biblioteki android.hardware.keymaster@*)

    Do *żadnego* z powyższych nie ma żadnej dokumentacji (oprócz high-level API), jedynym dostępnym zasobem jest niezbyt czytelny kod w AOSP który jest napisany tak że łączy elementy "klienta" i "serwera" w tym protokole w jednych funkcjach, przez co ciężko to ogarnąć. Musiałem zrozumieć jak działa binder dosyć dogłębnie aby pojąć co tam się dzieje, i w sumie sporo się mógłbym na ten temat rozpisać
    Cały debugging i wszystko z tym związane robiłem na moich zrootowanych telefonach oraz na tym pixelu, przy pomocy hooku LD_PRELOAD który napisałem który robi względnie czytelny dump wszystkich transakcji binderowych

    Celem tego wszystkiego było 1) usunięcie zależności od AOSP i 2) zrozumienie jak to wszystko działa

    * po tym jak już zrobiłem cały wrapper do HIDL keymaster HALa, zająłem się tym o czym miał być mój projekt, czyli userdata encryption. Patrząc po tym jak działają `LockSettingsService`, `vold` oraz inne systemowe rzeczy zreimplementowałem całą logikę odblokowania CE storage. Jednak to testowałem na moich telefonach od androida 9 - 14, nie miałem jeszcze poprawnie zrootowanego grapheneOSa więc to odłożyłem na później


    Ogólnie to uwierzytelnienie w celu odszyfrowania klucza może się odbywać w dwóch różnych trybach - przy pomocy starszego Gatekeepera i nowszego Weavera (ten wspiera też Strongbox). Oprócz tego, z każdym z tych dwóch HALi można się komunikować zarówno przez starszy HIDL jak i  nowszy AIDL.
    Z racji tego że wszystkie moje urządzenia mają HIDL/Gatekeeper, to według tego zrobiłem wsparcie.
    Należy jednak zaznaczyć że całą logikę odszyfrowywania i derywowania tych wszystkich kluczy i hashy i niewiadomo czego zrobiłem w całości, jedyne co mi w tej kwestii zostało to komunikacja (jeden call w zasadzie) do AIDL Gatekeeper i HIDL & AIDL Weaver.

    * Jak już zrobiłem te userdata rzeczy w moim narzędziu, to zabrałem się za
        1) grapheneOS; pobrałem i skompilowałem wersję userdebug, próbowałem też skompilować customowy kernel ale niespecjalnie chciało to działać więc skoro i tak miałem roota (userdebug build) to uznałem że dam sobie spokój z kernelem
        2) Posprzątanie, refactor i zgeneralizowanie mojego kodu. Miałem kilka tysięcy linijek kodu definicji do API keymastera i wszystko to zcentralizowałem w jednym pliku  przy pomocy makr, dzięki czemu kod używający tego (np do dumpowania structów keymasterowych) automatycznie używa nowych definicji bez potrzeby pisania ogrmnej ilości boilerplateu w pięciu różnych miejscach.

    * Później się zabrałem za wsparcie całego protokołu komunikacyjnego AIDL, na którym działa KeyMint - następca Keymastera.
    Warstwę komunikacji ze sterownikiem binder mogłem użyć tutaj bez większych zmian, ale za to musiałem zreimplementować
        * Parcele (mają inny format i zasadę działania niż te w HIDL)
        * Działające na parcelach prymitywy AIDL
        * Używające tych prymityw funkcje do ser/des typów KeyMint
        * No i na końcu zintegrować to z moim wrapperem starszego Keymastera.


W tym momencie jestem na w.w. etapie ser/des typów KeyMint i generalnie cały ten HAL myślę że dzisiaj ogarnę.
Jeśli wieczorem mi zostanie czasu, użyję też moich prymitywów HIDL i AIDL do zrobienia uwierzytelniania z Weaverem.

Cały etap AIDL/KeyMint robię na pixelu, bo żaden inny mój telefon nie ma tego HALu, działają na starszym Keymasterze pomimo tego że są na względnie nowych androidach (14, 15), ale to są Samsungi więc wiadomo jak jest

Ogólnie planowałem jutro udokumentować wszystko, chociaż warto zaznaczyć że API wszystkich moich bibliotek do HIDL, AIDL i bindera jest w miarę dobrze opisane w headerach.
Patrząc jednak na to ile wiedzy zdobyłem na temat działania wcześniej nieudokumentowanych rzeczy, chciałem zrobić coś ładniejszego na kształt bardziej wiki/blog posta no ale raczej nie zdążę.

We wszystkim używałem internetu i różnych czatów na tyle na ile mogłem, ale generalnie przez to jak mało informacji o tym jest online to  te chatboty się wywalały na nawet najprostzych, najbardziej machinalnych zadaniach, więc w zasadzie wszystko i tak zrobiłem sam, nawet te najbardziej żmudne części.
Ogólnie planuję dalej rozwijać projekt i dokumentację, więc to czego nie zdążę zrobić tutaj na praktyakch pewnie prędzej czy później wyląduje w repozyturium (https://github.com/jsoltan226/suskeymaster)

Tutaj jest ogólna struktura rzeczy które robiłem:
`libsuskmhal` zawiera bibliotekę(i) do komunikacji z HALami oraz definicje HALu Keymaster, i też klasę wrapperową C++ która "spina" różne wersję keymastera ze sobą.
 `libsuskmhal/transport` zawiera
 całą część kodu odpowiedzialną za te wszystkie rzeczy od prymityw HIDL/AIDL do interfejsu z binderem.
`cli` zawiera już samo narzędzie, napisane w C++, które używa w.w. `libsuskmhal` aby zrobić wygodny interfejs do tych wszystkich  HALowych funkcji.
Interesujące ciebie części najpewniej znajdziesz w `vold.cpp`, `gatekeeper.cpp` oraz w odpowidnich handlerach w `main.cpp`.

Oprócz tego:
`cgd/core` zawiera moje "rozszerzenia do libc" z mojego innego projektu (silnik do gier)
`libsuscertmod` zawiera tą "oryginalną" część tego projektu,  czyli coś co modyfikuje certyfikaty attestacji Keymaster i podpisuje je moimi wyekstraktowanymi kluczami (oczywiście w repozytorium ich nie ma).
`libsuskeymaster` zawiera sam hook do Keymaster HALa, który wywołuje `libsuscertmod` na przechwyconym certyfikacie. Ten hook jest napisany konkretnie na moje urządzenie i moją wersję systemu, więc raczej nie będzie działać nigdzie indziej bez modyfikacji

W `libsuscertmod/external` znajduje się też prebuilt libcrypto który linkuję do libsuskeymaster oraz androidowej wersji cli, ponieważ systemowe libcrypto sprawiało mi dużo problemów związanych z niekompatybilnym ABI itd.
Stąd też najpewniej te "40MB kodu" które widziałeś

Żeby zbudować mój projekt, używam takich komend:

```
export CC=/path/to/android-ndk/bin/aarch64-linux-android34-clang
export CXX=/path/to/android-ndk/bin/aarch64-linux-android34-clang++
export STRIP=aarch64-linux-gnu-strip # z aarch64 binutils
make -f Makefile.android -j$(nproc) release
```

lub żeby zbudować ograniczoną wersję cli która działa na hoście:
```
CC=cc CXX=c++ STRIP=strip make -f Makefile.host -j$(nproc) release
```

`make -f Makefile.*` po prostu bez żadnych targetów robi debugowy build z ASANem i debug symbolami,
chociaż jeśli się zmienia target (host/ android) to trzeba najpierw zrobić `make -f Makefile.(którykolwiek) clean`

Mam nadzieję że mój esej nie zabierze za dużo Twojego czasu :)
