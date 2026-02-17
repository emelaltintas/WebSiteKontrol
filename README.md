# WebSiteKontrol (AD Girisli)

Bu proje artik ASP.NET Core backend ile calisir. Kullanici girisi LDAP/AD ile dogrulanir.

## 1) LDAP Ayari

`appsettings.json` icindeki `Ldap` bolumunu sunucuna gore guncelle:

- `Server`: AD/LDAP sunucu adresi
- `Port`: genelde `636` (LDAPS)
- `UseSsl`: `true`
- `BaseDn`: ornek `DC=kastamonu,DC=local`
- `Domain`: ornek `kastamonu`
- `UpnSuffix`: ornek `kastamonu.edu.tr`

## 2) Local Calistirma

```bash
cd /Users/emelaltintas/Projects/WebSiteKontrol
./run-local.sh
```

veya:

```bash
npm run dev
```

Varsayilan port `5500`'dur. Farkli port:

```bash
./run-local.sh 8080
```

Tarayicida ac:

- http://127.0.0.1:5500

## 3) Giris

- E-posta veya kullanici adi + parola ile giris yapilir.
- Basarili giris sonrasi ana izleme sayfasi acilir.
- Giris yapmadan `/` ve `/index.html` erisimi kapatilidir.

## 4) Arka Plan Izleme ve E-posta Alarmi

Uygulama acik kaldigi surece arka planda URL kontrolu yapar.
Bir site `AKTIF -> PASIF` olursa alarm maili gonderir.

`appsettings.Production.json` icinde:

- `Monitoring.Enabled`: `true`
- `Monitoring.IntervalSeconds`: kontrol sikligi (ornek `300`)
- `Smtp.Enabled`: `true` yap
- `Smtp.Host`, `Smtp.Port`, `Smtp.Username`, `Smtp.Password`, `Smtp.From` degerlerini doldur
- `Smtp.To` listesine alici mail adreslerini yaz
