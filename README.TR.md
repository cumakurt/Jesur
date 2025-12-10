# JESUR - Gelişmiş SMB Paylaşım Tarayıcısı

**Versiyon**: 2.0.0  
**Geliştirici**: cumakurt  
**GitHub**: https://github.com/cumakurt/Jesur  
**LinkedIn**: https://www.linkedin.com/in/cuma-kurt-34414917/

**Sızma Testi Uzmanları İçin Profesyonel SMB Tarama ve Analiz Aracı**

JESUR, ağlar üzerindeki SMB paylaşımlarını taramak, erişim izinlerini analiz etmek, hassas dosyaları tespit etmek ve detaylı raporlar oluşturmak için tasarlanmış kapsamlı bir Python uygulamasıdır. Sızma testi uzmanları ve güvenlik profesyonelleri için geliştirilmiştir.

## 🚀 Özellikler

### Temel Yetenekler
- **Otomatik SMB Paylaşım Keşfi** - Tüm ağları veya belirli IP aralıklarını tarama
- **Çoklu Kimlik Doğrulama** - Anonim, Kullanıcı Adı/Şifre, NTLM Hash
- **Gerçek Paralel Tarama** - Yapılandırılabilir thread sayısı ile çoklu thread tarama
- **Hassas İçerik Tespiti** - Kimlik bilgileri, tokenlar ve sırlar için gelişmiş pattern eşleştirme
- **Profesyonel Raporlama** - Grafik ve istatistiklerle interaktif HTML raporları
- **Çoklu Export Formatları** - HTML, JSON, CSV export
- **Yapılandırma Dosyası Desteği** - Kurumsal düzeyde yapılandırma yönetimi
- **Gerçek Zamanlı İlerleme** - ETA hesaplaması ile canlı ilerleme takibi

### Gelişmiş Özellikler
- **Dosya İçerik Analizi** - PDF, DOCX, XLSX, Metin ve daha fazlası desteği
- **Akıllı Filtreleme** - Uzantı, boyut, dosya adı pattern'leri ile filtreleme
- **Hız Sınırlama** - Ağ aşırı yükünü önlemek için tarama hızını kontrol etme
- **IP Hariç Tutma Listeleri** - Belirli IP'leri veya ağları atlama
- **Paylaşım Filtreleme** - Belirli paylaşımları dahil et/hariç tut
- **Coğrafi Konum Taraması** - Ülke kodu ile IP aralıklarını tarama
- **Zaman Aşımı Koruması** - Takılmaları önlemek için host başına timeout
- **Zarif Kapanış** - Ctrl+C ile güvenli kesinti

## 📋 İçindekiler

- [Kurulum](#kurulum)
  - [Seçenek 1: Docker Kurulumu](#seçenek-1-docker-kurulumu-önerilen)
  - [Seçenek 2: Geleneksel Kurulum](#seçenek-2-geleneksel-kurulum)
  - [📖 Detaylı Kurulum Rehberi](INSTALL.TR.md)
- [Hızlı Başlangıç](#hızlı-başlangıç)
- [Yapılandırma Dosyası](#yapılandırma-dosyası)
- [Kullanım Örnekleri](#kullanım-örnekleri)
  - [Docker Kullanım Örnekleri](#docker-kullanım-örnekleri)
- [Komut Satırı Seçenekleri](#komut-satırı-seçenekleri)
- [Hassas Dosya Tespiti](#hassas-dosya-tespiti)
- [Hassas İçerik Tespiti](#hassas-içerik-tespiti)
- [Çıktı Formatları](#çıktı-formatları)
- [Performans Ayarları](#performans-ayarları)
- [Güvenlik Notları](#güvenlik-notları)
- [Sorun Giderme](#sorun-giderme)
- [Katkıda Bulunma](#katkıda-bulunma)
- [Lisans](#lisans)

## 🔧 Kurulum

> 📖 **Detaylı kurulum talimatları için**, [INSTALL.TR.md](INSTALL.TR.md) dosyasına bakın - Docker, Python sanal ortamları, sistem geneli kurulum ve sorun giderme konularını kapsayan kapsamlı rehber.

### Gereksinimler
- Python 3.7 veya üzeri (Docker kullanıyorsanız Python 3.12)
- Hedef SMB paylaşımlarına ağ erişimi
- Docker (opsiyonel, konteynerli kurulum için - önerilir)

### Seçenek 1: Docker Kurulumu (Önerilen)

Docker, tüm bağımlılıkların önceden yüklü olduğu izole bir ortam sağlar.

#### Docker ile Hızlı Başlangıç

```bash
# Repository'yi klonlayın
git clone https://github.com/cumakurt/Jesur.git
cd Jesur

# Docker imajını oluşturun
docker build -t jesur:latest .

# Tarama çalıştırın
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre
```

#### Docker Compose (Daha Kolay Yönetim)

```bash
# docker-compose.yml kullanarak
docker-compose run --rm jesur 192.168.1.0/24 -u kullanici -p sifre

# Veya docker-compose.yml'i düzenleyip çalıştırın:
docker-compose up
```

#### Docker Örnekleri

**⚠️ UNUTMAYIN: Dosyaları kendi makinenize kaydetmek için her zaman `-v` (volume mount) kullanın!**

**Tek IP Taraması:**
```bash
# ÖNCE kendi makinenizde dizin oluşturun
mkdir -p out_download

# Tarama çalıştırın - dosyalar KENDİ ./out_download dizininize kaydedilir
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest 192.168.1.1 -u admin -p sifre123

# Dosyaların kendi makinenizde olduğunu doğrulayın (konteyner içinde değil)
ls -la out_download/
```

**Config Dosyası ile Ağ Taraması:**
```bash
# KENDİ makinenizde config dosyasını kopyalayın ve düzenleyin
cp jesur.conf.example jesur.conf
nano jesur.conf

# KENDİ makinenizde çıktı dizinlerini oluşturun
mkdir -p out_download reports

# Mount edilmiş config ve çıktı dizinleri ile çalıştırın
docker run --rm --network host \
  -v $(pwd)/jesur.conf:/app/jesur.conf:ro \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest

# Tüm dosyalar KENDİ yerel dizinlerinize kaydedilir
ls -la out_download/ reports/
```

**Özel Çıktı Dizini ile Tarama (Mutlak Yollar):**
```bash
# KENDİ makinenizdeki özel konumlar için mutlak yollar kullanın
docker run --rm --network host \
  -v /home/kullanici/taramalarim/out_download:/app/out_download \
  -v /home/kullanici/taramalarim/reports:/app/reports \
  jesur:latest 10.0.0.0/24 -u kullanici -p sifre --output-name ozel_tarama

# Dosyalar kendi makinenizdeki /home/kullanici/taramalarim/ dizinine kaydedilir
ls -la /home/kullanici/taramalarim/out_download/
ls -la /home/kullanici/taramalarim/reports/
```

**Windows Örneği:**
```bash
# Windows - ileri eğik çizgi veya kaçış karakterli geri eğik çizgi kullanın
docker run --rm --network host \
  -v C:/Users/Adiniz/taramalar/out_download:/app/out_download \
  -v C:/Users/Adiniz/taramalar/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre

# Dosyalar kendi Windows makinenizdeki C:\Users\Adiniz\taramalar\ dizinine kaydedilir
```

**❌ YANLIŞ - Dosyalar Kaybolacak:**
```bash
# BUNU YAPMAYIN - Volume mount yok!
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre
# Tüm raporlar ve indirmeler konteyner içinde kalır ve durduğunda SİLİNİR!
```

**Sadece Paylaşımları Listele:**
```bash
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u guest -p "" --list-shares
```

**Detaylı Mod ile Hız Sınırlaması:**
```bash
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre \
  --verbose --rate-limit 10 --threads 20
```

**Docker Compose ile Özel Komut:**
```yaml
# docker-compose.yml'i düzenleyin
services:
  jesur:
    # ... mevcut yapılandırma ...
    command: ["python3", "Jesur.py", "192.168.1.0/24", "-u", "kullanici", "-p", "sifre", "--verbose"]
```

Sonra çalıştırın:
```bash
docker-compose up
```

#### Docker Volume Mount'ları

**⚠️ KRİTİK: Volume mount'lar dosyaları kendi makinenize kaydetmek için GEREKLİDİR!**

Volume mount'lar (`-v`) konteyner dizinlerini **KENDİ bilgisayarınızdaki** dizinlere bağlar. Bunlar olmadan, konteyner durduğunda tüm dosyalar kaybolur.

**Gerekli Volume Mount'lar:**

- **`/app/out_download`** → İndirilen hassas dosyalar için kendi yerel dizininize bağlanır
  ```bash
  -v $(pwd)/out_download:/app/out_download
  # Konteynerin /app/out_download'ına kaydedilen dosyalar KENDİ ./out_download/ dizininizde görünür
  ```

- **`/app/reports`** → Oluşturulan raporlar (HTML, JSON, CSV) için kendi yerel dizininize bağlanır
  ```bash
  -v $(pwd)/reports:/app/reports
  # Konteynerin /app/reports'una kaydedilen raporlar KENDİ ./reports/ dizininizde görünür
  ```

**Opsiyonel Volume Mount'lar:**

- **`/app/jesur.conf`** → Yapılandırma dosyası (salt okunur önerilir)
  ```bash
  -v $(pwd)/jesur.conf:/app/jesur.conf:ro
  # :ro = salt okunur, konteynerin config dosyanızı değiştirmesini önler
  ```

- **`/app/networks.txt`** → `--file` seçeneği kullanılıyorsa ağ listesi dosyası
  ```bash
  -v $(pwd)/networks.txt:/app/networks.txt:ro
  ```

**Tüm Mount'larla Tam Örnek:**
```bash
# 1. KENDİ makinenizde dizinleri oluşturun
mkdir -p out_download reports

# 2. Tüm volume mount'larla çalıştırın
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/jesur.conf:/app/jesur.conf:ro \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre

# 3. Dosyaların kendi makinenizde olduğunu doğrulayın
ls -la out_download/  # İndirilen dosyalar BURADA
ls -la reports/       # Raporlar BURADA
```

**Volume Mount Sözdizimini Anlama:**
```bash
-v HOST_YOLU:KONTEYNER_YOLU
-v $(pwd)/out_download:/app/out_download
   ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^
   Kendi makineniz      Konteyner içi
```

**Volume Mount'ların Çalıştığını Doğrulama:**
```bash
# Test taraması çalıştırın
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest 127.0.0.1 -u guest -p "" --list-shares

# Dizinin kendi makinenizde var olduğunu kontrol edin
ls -la out_download/

# Boşsa, bu list-shares için normaldir. Dosyaların görünmesi için gerçek bir tarama deneyin.
```

#### Docker Ağ Modları

**Host Network (SMB için Önerilen):**
```bash
docker run --rm --network host ...
```
- SMB portlarına (445, 139) doğrudan erişim
- Port mapping gerekmez
- En iyi performans

**Bridge Network (Alternatif):**
```bash
docker run --rm -p 445:445 -p 139:139 ...
```
- Port mapping gerektirir
- Bağlantı sorunları olabilir

### Seçenek 2: Geleneksel Kurulum

#### Bağımlılıkları Yükleme

```bash
# Repository'yi klonlayın
git clone https://github.com/cumakurt/Jesur.git
cd Jesur

# Gereksinimleri yükleyin
pip install -r requirements.txt
```

#### Gerekli Kütüphaneler
```
pysmb==1.2.10
jinja2==3.1.3
ipaddress==1.0.23
python-docx==0.8.11
openpyxl==3.1.2
pdfplumber==0.10.3
python-magic==0.4.27
requests==2.31.0
```

**Not:** Linux'ta `libmagic` sistem kütüphanesini yüklemeniz gerekebilir:
```bash
# Debian/Ubuntu
sudo apt-get install libmagic1

# CentOS/RHEL
sudo yum install file-devel

# macOS
brew install libmagic
```

## 🚀 Hızlı Başlangıç

### Temel Ağ Taraması

```bash
# Tek bir ağı tarama
python3 Jesur.py 192.168.1.0/24

# Dosyadan tarama
python3 Jesur.py -f networks.txt

# Kimlik doğrulama ile tarama
python3 Jesur.py 192.168.1.0/24 -u administrator -p Password123 -d DOMAIN
```

### Yapılandırma Dosyası Kullanımı

```bash
# jesur.conf dosyasını ayarlarınızla düzenleyin
# Ardından parametresiz çalıştırın (config varsayılanlarını kullanır)
python3 Jesur.py

# Veya komut satırı ile config'i geçersiz kılın
python3 Jesur.py --config custom.conf 192.168.1.0/24 --threads 50
```

## ⚙️ Yapılandırma Dosyası

JESUR, kurumsal dağıtımlar için bir yapılandırma dosyası (`jesur.conf`) destekler. Tüm parametreler config dosyasında ayarlanabilir veya komut satırı ile geçersiz kılınabilir.

### Örnek Yapılandırma (`jesur.conf`)

```ini
[scan]
network=192.168.1.0/24
threads=20
rate_limit=0
host_timeout=180

[auth]
username=guest
password=
domain=WORKGROUP

[filters]
include_ext=
exclude_ext=.log,.tmp
min_size=0
max_size=50485760
max_read_bytes=1048576
exclude_shares=IPC$,ADMIN$,C$
include_admin_shares=false

[output]
output_json=true
output_csv=false
output_name=jesur
quiet=false
verbose=false
```

### Yapılandırma Bölümleri

- **`[scan]`** - Tarama parametreleri (ağ, thread'ler, timeout'lar)
- **`[auth]`** - Kimlik doğrulama bilgileri
- **`[filters]`** - Dosya ve paylaşım filtreleme seçenekleri
- **`[output]`** - Çıktı formatı ve isimlendirme

## 💻 Kullanım Örnekleri

### Docker Kullanım Örnekleri

**Temel Docker Taraması:**
```bash
# İmajı bir kez oluşturun
docker build -t jesur:latest .

# Tarama çalıştırın
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre
```

**Tüm Seçeneklerle Docker:**
```bash
docker run --rm --network host \
  -v $(pwd)/jesur.conf:/app/jesur.conf:ro \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest 192.168.1.0/24 \
  -u admin -p sifre123 \
  --threads 30 \
  --rate-limit 20 \
  --verbose \
  --output-json \
  --output-csv
```

**Docker Compose İş Akışı:**
```bash
# 1. ÖNCE kendi makinenizde çıktı dizinlerini oluşturun
mkdir -p out_download reports

# 2. Gerekirse docker-compose.yml'i düzenleyin (volume'lar zaten yapılandırılmış)
nano docker-compose.yml

# 3. Tarama çalıştırın - volume'lar otomatik olarak kendi mevcut dizininize bağlanır
docker-compose run --rm jesur 192.168.1.0/24 -u kullanici -p sifre

# 4. Sonuçları kendi makinenizde görüntüleyin (konteyner içinde değil)
ls -la out_download/  # İndirilen dosyalar BURADA kendi makinenizde
ls -la reports/       # Raporlar BURADA kendi makinenizde
```

**docker-compose.yml volume'larını anlama:**
```yaml
volumes:
  # Bunlar konteyner dizinlerini KENDİ yerel dizinlerinize bağlar
  - ./out_download:/app/out_download    # Konteyner → KENDİ ./out_download/
  - ./reports:/app/reports              # Konteyner → KENDİ ./reports/
```

**Docker İnteraktif Mod (Hata Ayıklama):**
```bash
# Konteyneri interaktif olarak çalıştırın
docker run -it --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest /bin/bash

# Konteyner içinde manuel çalıştırın
python3 Jesur.py 192.168.1.0/24 -u kullanici -p sifre --verbose
```

### Temel Tarama

```bash
# Tek ağ taraması
python3 Jesur.py 192.168.1.0/24

# Dosyadan çoklu ağ taraması
python3 Jesur.py -f targets.txt

# Ülke bazlı tarama
python3 Jesur.py --geo tr_TR  # Türkiye
python3 Jesur.py --geo us_US  # Amerika Birleşik Devletleri
python3 Jesur.py --geo-list   # Tüm ülkeleri listele
```

### Kimlik Doğrulama Yöntemleri

```bash
# Domain kullanıcısı ile şifre
python3 Jesur.py 192.168.1.0/24 -u admin -p Password123 -d COMPANY

# Misafir erişimi (varsayılan)
python3 Jesur.py 192.168.1.0/24

# NTLM hash kimlik doğrulama (Pass-the-Hash)
# Format: LMHASH:NTHASH (her ikisi de 32 hex karakter olmalı)
python3 Jesur.py 192.168.1.0/24 -u administrator \
  --hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Domain ile hash kimlik doğrulama
python3 Jesur.py 192.168.1.0/24 -u administrator -d DOMAIN \
  --hashes aad3b435b51404eeaad3b435b51404ee:dd1709faebc6745c7be95fa7d452a01b

# Hash kimlik doğrulama (tek IP)
python3 Jesur.py 192.168.1.1 -u kullanici --hashes LMHASH:NTHASH
```

**Hash Kimlik Doğrulama Notları:**
- Hem LM hem de NT hash'leri `LMHASH:NTHASH` formatında sağlanmalıdır
- Her hash tam olarak 32 hexadecimal karakter olmalıdır
- Sadece NT hash'iniz varsa, boş LM hash kullanın: `aad3b435b51404eeaad3b435b51404ee:NTHASH`
- Domain parametresi (`-d`) domain ortamları için önerilir
- Hem NTLMv1 hem de NTLMv2 protokolleri ile çalışır

### Gelişmiş Filtreleme

```bash
# Sadece belirli uzantıları dahil et
python3 Jesur.py 192.168.1.0/24 --include-ext txt,ini,config,xml

# Binary dosyaları hariç tut
python3 Jesur.py 192.168.1.0/24 --exclude-ext exe,dll,bin,iso

# Dosya boyutu filtreleme (1KB - 5MB)
python3 Jesur.py 192.168.1.0/24 --min-size 1024 --max-size 5242880

# Dosya adı pattern eşleştirme (regex)
python3 Jesur.py 192.168.1.0/24 --filename-pattern ".*password.*|.*secret.*"

# Belirli paylaşımları hariç tut
python3 Jesur.py 192.168.1.0/24 --exclude-shares "PRINT$,FAX$"

# Admin paylaşımlarını dahil et (varsayılan: hariç)
python3 Jesur.py 192.168.1.0/24 --include-admin-shares
```

### Performans Ayarları

```bash
# Yüksek hızlı tarama (50 thread)
python3 Jesur.py 192.168.1.0/24 --threads 50

# Hız sınırlı tarama (saniyede 5 IP)
python3 Jesur.py 192.168.1.0/24 --rate-limit 5

# Özel host timeout (300 saniye)
python3 Jesur.py 192.168.1.0/24 --host-timeout 300

# Dosya okuma boyutu sınırı (512KB maksimum)
python3 Jesur.py 192.168.1.0/24 --max-read-bytes 524288
```

### Export Seçenekleri

```bash
# JSON export
python3 Jesur.py 192.168.1.0/24 --output-json

# CSV export
python3 Jesur.py 192.168.1.0/24 --output-csv

# Her iki format + özel isim
python3 Jesur.py 192.168.1.0/24 --output-json --output-csv --output-name pentest_2024

# Sessiz mod (minimal çıktı)
python3 Jesur.py 192.168.1.0/24 --quiet --output-json

# Detaylı mod (tüm loglar)
python3 Jesur.py 192.168.1.0/24 --verbose
```

### Gerçek Dünya Senaryoları

```bash
# SENARYO 1: Hızlı keşif (sadece paylaşım listesi)
python3 Jesur.py 192.168.0.0/16 --list-shares --threads 50 --quiet

# SENARYO 2: Kimlik bilgisi avı (sadece config dosyaları)
python3 Jesur.py 192.168.1.0/24 --include-ext ini,conf,config,xml,yaml,json --verbose

# SENARYO 3: Gizli tarama (yavaş ve sessiz)
python3 Jesur.py 10.0.0.0/8 --rate-limit 2 --threads 5 --quiet

# SENARYO 4: Büyük ağ taraması
python3 Jesur.py -f corporate_networks.txt --threads 50 \
  --exclude-file exclude_list.txt --output-json

# SENARYO 5: Ülke geneli tarama
python3 Jesur.py --geo tr_TR --threads 100 --quiet \
  --output-json --output-csv
```

## 📖 Komut Satırı Seçenekleri

### Hedef Belirtme

| Seçenek | Açıklama | Örnek |
|---------|----------|-------|
| `network` | CIDR formatında ağ | `192.168.1.0/24` |
| `-f, --file` | Ağ listesi dosyası | `-f targets.txt` |
| `--geo` | Ülke kodu | `--geo tr_TR` |
| `--geo-list` | Ülke kodlarını listele | `--geo-list` |

### Kimlik Doğrulama

| Seçenek | Açıklama | Varsayılan |
|---------|----------|------------|
| `-u, --username` | Kullanıcı adı | `guest` |
| `-p, --password` | Şifre | (boş) |
| `--hashes` | `LMHASH:NTHASH` formatında NTLM hash (her biri 32 hex karakter) | Yok |
| `-d, --domain` | Domain adı | `WORKGROUP` |

**Kimlik Doğrulama Önceliği:**
- `--hashes` sağlanırsa, hash kimlik doğrulama kullanılır (şifre yok sayılır)
- `-p` sağlanır ve `--hashes` yoksa, şifre kimlik doğrulama kullanılır
- Hiçbiri sağlanmazsa, anonim/misafir erişimi denenir

### Tarama Seçenekleri

| Seçenek | Açıklama | Varsayılan |
|---------|----------|------------|
| `--share` | Belirli paylaşımı tara | Tümü |
| `--list-shares` | Sadece paylaşım listesi | False |
| `--threads` | Thread sayısı | Otomatik (10-100) |
| `--rate-limit` | Saniyede IP sayısı | 0 (sınırsız) |
| `--host-timeout` | Host başına timeout (saniye) | 180 |

### Filtreleme Seçenekleri

| Seçenek | Açıklama | Varsayılan |
|---------|----------|------------|
| `--include-ext` | Dahil edilecek uzantılar | Tümü |
| `--exclude-ext` | Hariç tutulacak uzantılar | Yok |
| `--min-size` | Min dosya boyutu (byte) | 0 |
| `--max-size` | Max dosya boyutu (byte) | 10MB |
| `--max-read-bytes` | Okunacak max byte | 1MB |
| `--filename-pattern` | Regex pattern | Yok |
| `--exclude-shares` | Hariç tutulacak paylaşımlar | Yok |
| `--include-admin-shares` | Admin paylaşımlarını dahil et | False |
| `--exclude-file` | IP hariç tutma dosyası | Yok |

### Çıktı Seçenekleri

| Seçenek | Açıklama | Varsayılan |
|---------|----------|------------|
| `--output-json` | JSON export | False |
| `--output-csv` | CSV export | False |
| `--output-name` | Çıktı dosya adı | `jesur` |
| `--quiet, -q` | Sessiz mod | False |
| `--verbose, -v` | Detaylı mod | False |
| `--no-stats` | İstatistik gösterme | False |
| `--config` | Config dosya yolu | `jesur.conf` |

## 🔍 Hassas Dosya Tespiti

JESUR aşağıdaki hassas dosya türlerini otomatik olarak tespit eder ve indirir:

### Parola Yöneticileri
- **KeePass**: Veritabanları (`.kdbx`, `.kdb`), Anahtar Dosyaları (`.key`)
- **1Password**: İçe Aktarma Dosyaları (`.1pif`), Kasa Dosyaları (`.opvault`)
- **LastPass**: Dışa Aktarma Dosyaları (`lastpass.csv`, `lastpass_export.csv`)
- **Bitwarden**: Veri Dosyaları (`data.json`, `bitwarden.json`)
- **Dashlane**: Veritabanı (`dashlane.db`)
- **RoboForm**: Veri Dosyası (`RoboForm.dat`)
- **Tarayıcı Şifreleri**: Chrome/Edge (`Login Data`, `Web Data`), Firefox (`key4.db`, `logins.json`)

### Uzak Bağlantı Araçları
- **PuTTY**: Özel Anahtarlar (`.ppk`)
- **Remote Desktop**: Ayarlar (`.rdp`, `.rdg`, `.rdm`)
- **Remmina**: Bağlantı Dosyaları (`.remmina`), Tercihler (`remmina.pref`)
- **SecureCRT**: Yapılandırma (`SecureCRT.ini`, `Global.ini`)
- **RoyalTS**: Bağlantı Paketleri (`.rtsz`, `.rtsx`)
- **SuperPuTTY**: Oturumlar (`SuperPuTTY.xml`, `sessions.xml`)
- **Terminals**: Yapılandırma (`terminals.config`, `terminals.xml`)
- **Remote Desktop Manager**: Yapılandırma (`RemoteDesktopManager.xml`)

### Bağlantı Yöneticileri
- **mRemoteNG**: Yapılandırma (`confCons.xml`)
- **WinSCP**: Yapılandırma (`WinSCP.ini`)
- **FileZilla**: Ayarlar (`FileZilla.xml`, `filezilla.xml`)
- **MobaXterm**: Yapılandırma (`MobaXterm.ini`)

### SSH Yapılandırması
- SSH Özel Anahtarları (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`)
- SSH Yapılandırma Dosyaları (`config`, `known_hosts`, `authorized_keys`)

### Sertifikalar ve Güvenlik
- SSL/TLS Sertifikaları (`.crt`, `.pem`, `.cer`)
- PKCS#12 (`.pfx`, `.p12`)
- Java KeyStore (`.jks`, `.keystore`)
- OpenVPN Yapılandırması (`.ovpn`)
- VNC Yapılandırması (`.vnc`)
- Sistem Dosyaları (`passwd`, `shadow`, `.htpasswd`)

### Bulut Kimlik Bilgileri
- **AWS**: Kimlik Bilgileri (`.aws/credentials`, `.aws/config`, `credentials.csv`)
- **Azure**: Profil (`azureProfile.json`), Kimlik Bilgileri (`azureCredentials.json`)
- **GCP**: Servis Hesapları (`service-account.json`), Yapılandırma (`.gcp/`)
- **Terraform**: Durum Dosyaları (`.tfstate`), Değişkenler (`.tfvars`)
- **HashiCorp Vault**: Yapılandırma (`vault.hcl`), Tokenlar (`.vault-token`)

### CI/CD ve Geliştirme
- **Jenkins**: Kimlik Bilgileri (`credentials.xml`), Yapılandırma (`config.xml`)
- **GitLab**: CI Yapılandırması (`.gitlab-ci.yml`), Sırlar (`gitlab-secrets.json`)
- **GitHub**: İş Akışları (`.github/workflows/`), Tokenlar (`GITHUB_TOKEN`)
- **Docker**: Yapılandırma (`config.json`), Compose (`docker-compose.yml`)
- **Kubernetes**: Yapılandırma (`kubeconfig`), Sırlar (`*.yaml`)
- **Ansible**: Kasa Dosyaları (`secrets.yml`, `vault_pass`)

### Ortam ve Yapılandırma Dosyaları
- Ortam Değişkenleri (`.env`, `.env.local`, `.env.production`)
- Yapılandırma Dosyaları (`config.ini`, `config.json`, `settings.json`)
- Uygulama Özellikleri (`application.properties`, `application.yml`)
- NPM Yapılandırması (`.npmrc`)
- PIP Yapılandırması (`pip.conf`, `.pypirc`)

### Veritabanı ve Yedek Dosyaları
- SQL Dökümleri (`.sql`, `.dump`)
- Veritabanı Dosyaları (`.db`, `.sqlite`, `.sqlite3`, `.mdb`)
- Yedek Dosyaları (`.bak`, `.backup`, `.old`, `.orig`)

### Git Kimlik Bilgileri
- Git Kimlik Bilgileri (`.git-credentials`)
- Git Yapılandırması (`.gitconfig`)

### Windows Kimlik Bilgileri
- Kimlik Bilgisi Yöneticisi (`Credentials.xml`)

### CyberArk
- Kasa Yapılandırması (`vault.ini`, `cyberark.config`)

### Oturum ve Token Dosyaları
- Oturum Dosyaları (`.session`, `session.dat`)
- Token Dosyaları (`.token`, `.api_key`)

## 🔎 Hassas İçerik Tespiti

JESUR dosya içeriklerinde şunları tarar:

- **Kimlik Bilgileri** - Kullanıcı adları, şifreler, API anahtarları
- **Tokenlar** - Kimlik doğrulama tokenları, oturum ID'leri
- **Veritabanı Bağlantıları** - Bağlantı dizileri, kimlik bilgileri
- **Bulut Kimlik Bilgileri** - AWS, Azure, GCP anahtarları
- **E-posta Bilgileri** - SMTP kimlik bilgileri, e-posta adresleri
- **Finansal Veriler** - Kredi kartları, ödeme bilgileri
- **Dahili IP'ler** - Özel ağ adresleri
- **Güvenlik Anahtar Kelimeleri** - Güvenlikle ilgili pattern'ler
- **Exploit Yükleri** - Sızma testi araçları

## 📊 Çıktı Formatları

### HTML Raporları

İki kapsamlı HTML raporu oluşturulur:

1. **Dosyalar Raporu** (`jesur_files_YYYYMMDD_HHMMSS.html`)
   - Tüm taranan dosyalar
   - Dosya metadata'sı (boyut, tarihler)
   - Arama ile interaktif tablolar
   - Görsel istatistik kartları
   - Grafikler ve çizelgeler

2. **Hassas Rapor** (`jesur_sensitive_YYYYMMDD_HHMMSS.html`)
   - Tespit edilen hassas içerik
   - Dosya indirme linkleri
   - İçerik önizleme ve kopyalama
   - Kategori sınıflandırması
   - İnteraktif görselleştirmeler

### JSON Export

```bash
python3 Jesur.py 192.168.1.0/24 --output-json
```

Oluşturur:
- `jesur_files_YYYYMMDD_HHMMSS.json` - Dosya listeleri
- `jesur_sensitive_YYYYMMDD_HHMMSS.json` - Hassas bulgular
- `jesur_stats_YYYYMMDD_HHMMSS.json` - Tarama istatistikleri

### CSV Export

```bash
python3 Jesur.py 192.168.1.0/24 --output-csv
```

Oluşturur:
- `jesur_files_YYYYMMDD_HHMMSS.csv` - Dosya listeleri
- `jesur_sensitive_YYYYMMDD_HHMMSS.csv` - Hassas bulgular

### İndirilen Dosyalar

Hassas dosyalar otomatik olarak şuraya indirilir:
```
out_download/[IP_ADRESI]/[dosya_adi]
```

## ⚡ Performans Ayarları

### Thread Yapılandırması

```bash
# Küçük ağ (< 10 host)
--threads 10

# Orta ağ (10-50 host)
--threads 20-30

# Büyük ağ (> 50 host)
--threads 50-100
```

### Hız Sınırlama

```bash
# Yavaş tarama (saniyede 2 IP)
--rate-limit 2

# Orta tarama (saniyede 10 IP)
--rate-limit 10

# Hızlı tarama (sınırsız)
--rate-limit 0
```

### Bellek Yönetimi

- Dosya cache: Maksimum 1000 giriş
- Paylaşım cache: Maksimum 500 giriş
- Maksimum bellek: 500MB
- Dosya başına limit: 10MB

## 🛡️ Güvenlik Notları

⚠️ **ÖNEMLİ**: Bu araç sadece yetkili sızma testleri için tasarlanmıştır.

- ⚠️ Yetkisiz ağ taraması yasadışı olabilir
- ⚠️ Sadece sahip olduğunuz veya açık izniniz olan ağlarda kullanın
- ⚠️ Hassas dosyalar otomatik olarak indirilir
- ⚠️ Tüm işlemler loglanır ve raporlanır
- ⚠️ Güvenli kapanış için Ctrl+C kullanın

## 🐛 Sorun Giderme

### Yaygın Sorunlar

**Bağlantı Zaman Aşımı**
```bash
# Host timeout'u artır
python3 Jesur.py 192.168.1.0/24 --host-timeout 300
```

**Bellek Sorunları**
```bash
# Max okuma byte'ını azalt
python3 Jesur.py 192.168.1.0/24 --max-read-bytes 512000
```

**Yavaş Tarama**
```bash
# Thread sayısını artır
python3 Jesur.py 192.168.1.0/24 --threads 50
```

**Kimlik Doğrulama Hataları**
```bash
# Detaylar için verbose mod kullan
python3 Jesur.py 192.168.1.0/24 -u user -p pass --verbose

# Hash kimlik doğrulama sorun giderme
python3 Jesur.py 192.168.1.0/24 -u user -d DOMAIN \
  --hashes LMHASH:NTHASH --verbose

# Docker versiyonu
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre --verbose

# Docker ile hash kimlik doğrulama
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u kullanici -d DOMAIN \
  --hashes LMHASH:NTHASH --verbose
```

**Docker Ağ Sorunları**
```bash
# SMB bağlantıları başarısız olursa, host network modunu kullanın
docker run --rm --network host ...

# Portların konteynerden erişilebilir olduğunu kontrol edin
docker run --rm --network host \
  jesur:latest --help

# Bağlantıyı test edin
docker run --rm --network host \
  jesur:latest 192.168.1.1 -u guest -p "" --list-shares
```

**Docker İzin Sorunları**
```bash
# Çıktı dizinlerinin yazılabilir olduğundan emin olun
mkdir -p out_download reports
chmod 777 out_download reports

# Veya belirli kullanıcı ile çalıştırın
docker run --rm --network host \
  -u $(id -u):$(id -g) \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre
```

## 📝 Ağ Dosyası Formatı

Bir dosya (`networks.txt`) oluşturun, her satıra bir ağ:

```text
# Yorumlar # ile başlar
192.168.1.0/24
10.0.0.0/24
172.16.1.1        # Tek IP (otomatik /32'ye dönüştürülür)
192.168.2.100/32  # Açık CIDR
```

## 🤝 Katkıda Bulunma

Katkılarınız memnuniyetle karşılanır! Lütfen:

1. Repository'yi fork edin
2. Bir feature branch oluşturun
3. Değişikliklerinizi yapın
4. Bir pull request gönderin

Büyük değişiklikler için lütfen önce bir issue açın.

## 📄 Lisans

Bu proje GNU General Public License v3.0 lisansı altında lisanslanmıştır - detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🙏 Teşekkürler

- Sızma testi uzmanları ve güvenlik profesyonelleri için geliştirilmiştir
- Kapsamlı SMB paylaşım analizi ihtiyacından ilham alınmıştır
- Tüm katkıda bulunanlara ve test edenlere teşekkürler

## 🔗 Bağlantılar

- **GitHub**: https://github.com/cumakurt/Jesur


---

**Sızma Testi Uzmanları İçin ❤️ ile Yapıldı**
