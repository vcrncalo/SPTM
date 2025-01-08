# Simulacije procesa u telekomunikacijskim mrežama - Dizajn i implementacija TOR modela u NS-3 simulatoru

## Opis projekta

U ns-3 simulatoru je potrebno kreirati TOR mrežu i simulirati istu. 

*Ovaj model simulira **TOR (The Onion Router)** mrežu i koristi sedam čvorova:*

- **Klijent** - Započinje slanje paketa (omogućava inicijalizaciju mrežnog saobraćaja),
- **Ulazni čvor** - Predstavlja prvi skok (hop),
- **Tri releja** - Omogućavaju prosljeđivanje mrežnog saobraćaja,
- **Izlazni čvor** - Ovo predstavlja posljednji čvor prije odredišta,
- **Odredište** - Predstavlja posljedni čvor u mreži koji prima pakete i naposljetku ih obrađuje.

Ovaj kod simulira osnovnu TOR mrežu koristeći ns-3 simulator. Omogućeno je kreiranje 7 čvorova, njihovo povezivanje u lanac, dodjeljivanje IP adresa tim čvorovima i postavljanje klijent-server aplikacije. Podaci su šifrirani pomoću AES-256-CBC enkripcijskog algoritma što omogućava OpenSSL-ova EVP biblioteka na svakom skoku. Simulacija prati protok paketa, računa mrežnu statistiku poput kašnjenja i omjera poslanih paketa, te vizualizira mrežu pomoću NetAnim alata (kreira se xml datoteka s nazivom tor-network-visualization.xml na kojoj su prikazani svi čvorovi). Također, ovaj kod omogućuje ispis statistike po čvoru. Simulacija traje deset sekundi.

---

## Funkcionalnost koda

*U nastavku je objašnjen način funkcionisanja TOR mreže implementirane u ns-3 simulatoru:*

| Stavka                        | Opis |
|-------------------------------|------|
| **Arhitektura simulacije**    | Simulacija uključuje 7 čvorova: klijent, ulazni čvor (Entry), tri čvora za releje (Relay 1, Relay 2, Relay 3), izlazni čvor (Exit), i krajnji odredišni čvor (Destination). Ova topologija imitira TOR mrežnu strukturu, gdje klijent šalje podatke kroz šifrirane kanale, prolazeći kroz više releja prije nego što stigne do odredišta. <br><br> **Mrežna topologija:** <br> - TOR Klijent šalje podatke kroz Entry Guard (ulazni čvor). <br> - Podaci se šifriraju i prolaze kroz releje (Relay 1, Relay 2, Relay 3). <br> - Na kraju, podaci izlaze kroz izlazni čvor i stižu do odredišnog čvora. <br><br> **Povezivanje čvorova:** <br> - Svaka veza između čvorova je ostvarena pomoću *PointToPointHelper*-a, koji koristi TCP/IP protokol i P2P (point-to-point) mreže za prijenos podataka. <br> - Svaka veza između čvorova je podešena sa *DataRate*-om (brzina prijenosa podataka) i *Delay*-om (kašnjenjem). |
| **Enkripcija i sigurnost**    | Jedan od ključnih aspekata TOR mreže je višeslojna enkripcija, što je implementirano pomoću OpenSSL EVP (Encryption/Decryption API) enkripcijskog algoritma. Kod koristi AES 256-bitnu CBC enkripciju za zaštitu podataka na svakom "skoku" u mreži. <br><br> **Ključne funkcije enkripcije:** <br> - **Generisanje ključeva:** Svaka enkripcijska sesija koristi nasumično generisane ključeve pomoću OpenSSL funkcije `RAND_bytes`. <br> - **Šifriranje i dešifrovanje podataka:** Funkcije `EncryptLayer` i `DecryptLayer` omogućavaju višeslojnu enkripciju, gdje podaci prolaze kroz više slojeva šifriranja i dešifrovanja, što je karakteristično za TOR mrežu. <br><br> **TOR paket struktura:** Paketi u TOR mreži imaju proširenu strukturu koja omogućava praćenje stanja svakog paketa tokom putovanja kroz mrežu: <br> - `sequenceNumber`: Jedinstveni broj sekvence za svaki paket. <br> - `data`: Podaci u paketu. <br> - `encryptionLayer`: Indikator sloja enkripcije. <br> - `timestamp`: Vrijeme kada je paket kreiran. <br> - `hopCount`: Broj "skokova" kroz mrežu. <br> - `sourceNode` i `destinationNode`: Naziv izvorišnog i odredišnog čvora. <br> - `circuitId`: Identifikator TOR kruga. <br> - `isControl`: Ukazuje na to da li je paket kontrolni paket ili ne. <br> - `encryptionLayers`: Lista slojeva enkripcije na svakom skoku u mreži. |
| **Simulacija i praćenje**     | **Početak i kraj simulacije:** <br> - Simulacija traje 10 sekundi, s različitim vremenskim okvirom za početak i završetak aplikacija. <br><br> **Praćenje mreže (Flow monitoring):** <br> - Korišćen je *FlowMonitor* za praćenje statistike mrežnog saobraćaja, uključujući podatke o paketu (transmisija, prijem, gubici) i kašnjenju. <br><br> **Metrike i statistika:** <br> - **Omjer poslanih i primljenih paketa (Packet delivery ratio):** Pokazuje omjer primljenih i poslanih paketa, što je važan indikator efikasnosti mreže. <br> - **Delay:** Prosječno kašnjenje za primljene pakete. <br> - **Statistika za svaki čvor:** Svaki čvor u mreži ima opis i informacije o svom stanju. |
| **Simulacija i vizualizacija** | **NetAnim:** <br> - Mreža je vizualizovana koristeći *NetAnim*, alat za animaciju mrežne topologije, koji prikazuje mrežnu topologiju i podatke o čvorovima. <br> - Boje čvorova su podešene tako da odražavaju njihove uloge (klijent, relays, izlaz, itd.). |
| **Dizajn TOR mreže**          | **Topologija čvorova:** <br> - Hijerarhija čvorova, kao što su ulazni čvor, releji, i izlazni čvor, simuliraju stvarni TOR dizajn. <br><br> **Enkripcija:** <br> - Upotreba višeslojne enkripcije sa ključevima koji se rotiraju na svakom skoku. <br><br> **Anonimnost i sigurnost:** <br> - Paketima se dodaju razni podaci (npr., `hopCount`, `timestamp`, `encryptionLayer`) kako bi se simuliralo ponašanje TOR mreže koja pruža anonimnost. |

---

## Simulacija

### Rezultati simulacije

*Prilikom pokretanja simulacije, pojavljuju se sljedeći ispis sa podacima o čvorovima mreže, prikazan na slikama 1, 2 i 3:*

<div align="center">
<table>
	<tr>
		<td><img src="Slike/Simulacija_1.png" alt="Simulacija_1"></td>
      		<td><img src="Slike/Simulacija_2.png" alt="Simulacija_2"></td>
    	</tr>
    	<tr>
      		<td><p align="center">Slika 1: Podaci o čvorovima: 0, 1 i 2</p></td>
      		<td><p align="center">Slika 2: Podaci o čvorovima: 3, 4 i 5</p></td>
    	</tr>
</table>
</div>

<p align="center">
<img src=Slike/Simulacija_3.png alt="Simulacija_3">
<br>
Slika 3: Podaci o šestom čvoru mreže
</p>

*Nakon tog ispisa, slijedi konačni ispis o broju poslatih i primljenih paketa, ukupnom kašnjenju i postotku primljenih paketa:*

<p align="center"><img src=Slike/Simulacija_konačni_ispis.png alt="Simulacija_konačni_ispis">
<br>
Slika 4: Mrežna statistika
</p>

### NetAnim

Kod za simulaciju TOR mreže u ns-3 simulatoru omogućava i kreiranje xml datoteke koja se može otvoriti u **NetAnim** softveru koji omogućava prikaz animacije mreže. 

*Na petoj slici je prikazana mreža sa svim čvorovima kada se xml datoteka tek otovori u NetAnim-u:*

<p align="center"><img src=Slike/NetAnim_početak_simulacije.png alt="NetAnim_početak_simulacije">
<br>
Slika 5: NetAnim - Početak simulacije
</p>

*Na šestoj slici je prikazan završetak simulacije u NetAnim-u:*

<p align="center"><img src=Slike/NetAnim_završetak_simulacije.png alt="NetAnim_završetak_simulacije">
Slika 6: NetAnim - Početak simulacije
</p>
