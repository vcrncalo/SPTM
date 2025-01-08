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

## Simulacija

### Rezultati simulacije

*Prilikom pokretanja simulacije, pojavljuju se sljedeći ispis sa podacima o čvorovima mreže, prikazan na slikama 1, 2 i 3:*

<p align="center">
<table>
	<tr>
		<td><img src=Slike/Simulacija_1.png alt="Simulacija_1"></td>

		<td><img src=Slike/Simulacija_2.png alt="Simulacija_2"></td>
	</tr>
	<tr>
		<td><p align="center">Slika 1: Podaci o čvorovima: 0, 1 i 2</p>
		<td><p align="center">Slika 2: Podaci o čvorovima: 3, 4 i 5</p>
	</tr>
</table>
</p>

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

*Na četvrtoj slici je prikazana mreža sa svim čvorovima kada se xml datoteka tek otovori u NetAnim-u:*

<p align="center"><img src=Slike/NetAnim_početak_simulacije.png alt="NetAnim_početak_simulacije">
<br>
Slika 5: NetAnim - Početak simulacije
</p>

*Na petoj slici je prikazan završetak simulacije u NetAnim-u:*

<p align="center"><img src=Slike/NetAnim_završetak_simulacije.png alt="NetAnim_završetak_simulacije">
Slika 5: NetAnim - Početak simulacije
</p>
