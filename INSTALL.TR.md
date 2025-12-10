# JESUR Kurulum Rehberi

JESUR - Enhanced SMB Share Scanner için kapsamlı kurulum rehberi

## İçindekiler

1. [Gereksinimler](#gereksinimler)
2. [Kurulum Yöntemleri](#kurulum-yöntemleri)
   - [Yöntem 1: Docker Kurulumu (Önerilen)](#yöntem-1-docker-kurulumu-önerilen)
   - [Yöntem 2: Python Sanal Ortamı](#yöntem-2-python-sanal-ortamı)
   - [Yöntem 3: Sistem Geneli Kurulum](#yöntem-3-sistem-geneli-kurulum)
   - [Yöntem 4: Geliştirme Kurulumu](#yöntem-4-geliştirme-kurulumu)
3. [Kurulum Sonrası Yapılandırma](#kurulum-sonrası-yapılandırma)
4. [Doğrulama](#doğrulama)
5. [Sorun Giderme](#sorun-giderme)
6. [Kaldırma](#kaldırma)

---

## Gereksinimler

### Sistem Gereksinimleri

- **İşletim Sistemi**: Linux, macOS veya Windows (WSL önerilir)
- **Python**: 3.7 veya üzeri
- **RAM**: Minimum 512MB, Önerilen 2GB+
- **Disk Alanı**: Uygulama için minimum 100MB, raporlar için ek alan
- **Ağ**: Hedef SMB paylaşımlarına erişim (portlar 445/139)

### Gerekli Sistem Kütüphaneleri

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip libmagic1 libmagic-dev
```

#### Linux (CentOS/RHEL/Fedora)
```bash
sudo yum install -y python3 python3-pip file-devel
# veya yeni sürümler için:
sudo dnf install -y python3 python3-pip file-devel
```

#### macOS
```bash
# Homebrew yüklü değilse yükleyin
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Bağımlılıkları yükleyin
brew install python3 libmagic
```

#### Windows
```bash
# Python'u python.org'dan yükleyin
# libmagic'ı pip ile yükleyin (python-magic-bin)
pip install python-magic-bin
```

### Docker Gereksinimleri (Opsiyonel)

- **Docker**: Sürüm 20.10 veya üzeri
- **Docker Compose**: Sürüm 1.29 veya üzeri (opsiyonel ama önerilir)

Docker kurulumunu kontrol edin:
```bash
docker --version
docker-compose --version
```

---

## Kurulum Yöntemleri

### Yöntem 1: Docker Kurulumu (Önerilen)

Docker en kolay ve en izole kurulum yöntemini sağlar. Tüm bağımlılıklar önceden yapılandırılmıştır.

#### Adım 1: Repository'yi Klonlayın

```bash
git clone https://github.com/cumakurt/Jesur.git
cd Jesur
```

#### Adım 2: Docker İmajını Oluşturun

```bash
docker build -t jesur:latest .
```

Bu işlem:
- Python 3.12-slim base imajını indirir
- Multi-stage build ile optimize edilmiş imaj oluşturur
- Sistem bağımlılıklarını yükler (libmagic, file, ca-certificates)
- requirements.txt'den Python paketlerini yükler
- Çalışma dizinini ve ortamı ayarlar

**Oluşturma süresi**: İnternet hızına bağlı olarak ~2-5 dakika (ilk build), sonraki build'lerde cache sayesinde daha hızlı

#### Adım 3: Kurulumu Doğrulayın

```bash
docker run --rm jesur:latest --help
```

Yardım menüsünü görmelisiniz.

#### Adım 4: Çıktı Dizinlerini Oluşturun (ÖNEMLİ!)

**⚠️ KRİTİK**: Docker konteynerleri geçicidir. Volume mount kullanmazsanız, tüm raporlar ve indirilen dosyalar konteyner durduğunda kaybolacaktır!

Kendi **makinenizde** dizinleri oluşturun (konteyner içinde değil):

```bash
# Mevcut konumunuzda dizinleri oluşturun
mkdir -p out_download reports

# Var olduklarını doğrulayın
ls -la out_download reports
```

**Neden bu önemli:**
- Docker konteyneri içinde oluşturulan dosyalar konteyner durduğunda **kaybolur**
- Volume mount'lar (`-v`) konteyner dizinlerini **kendi makinenize** bağlar
- Raporlar ve indirmeler konteyner kaldırılsa bile **bilgisayarınızda** kalır

#### Adım 5: Volume Mount'larla İlk Taramanızı Çalıştırın

**Temel Örnek:**
```bash
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre
```

**Ne olur:**
- `-v $(pwd)/out_download:/app/out_download` konteynerin `/app/out_download` dizinini mevcut dizininizdeki `out_download` klasörüne bağlar
- `-v $(pwd)/reports:/app/reports` konteynerin `/app/reports` dizinini mevcut dizininizdeki `reports` klasörüne bağlar
- Konteyner içinde `/app/out_download` ve `/app/reports`'a kaydedilen tüm dosyalar yerel dizinlerinizde görünür

**Dosyaların kendi makinenizde olduğunu doğrulayın:**
```bash
# Tarama tamamlandıktan sonra yerel dizinlerinizi kontrol edin
ls -la out_download/
ls -la reports/
# HTML, JSON, CSV dosyaları ve indirilen hassas dosyaları görmelisiniz
```

**Özel Çıktı Dizini Örneği:**
```bash
# Özel konumlar için mutlak yollar kullanın
docker run --rm --network host \
  -v /home/kullanici/taramalarim/out_download:/app/out_download \
  -v /home/kullanici/taramalarim/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre

# Dosyalar kendi makinenizdeki /home/kullanici/taramalarim/ dizinine kaydedilir
```

**Windows Örneği:**
```bash
# Windows yolları (ileri eğik çizgi veya kaçış karakterli geri eğik çizgi kullanın)
docker run --rm --network host \
  -v C:/Users/Adiniz/taramalar/out_download:/app/out_download \
  -v C:/Users/Adiniz/taramalar/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre
```

**Volume Mount Olmadan (YANLIŞ - Dosyalar kaybolacak!):**
```bash
# ❌ BUNU YAPMAYIN - Dosyalar kaybolacak!
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre
# Tüm raporlar ve indirmeler konteyner içinde kalır ve durduğunda silinir
```

#### Docker Compose Kurulumu

Daha kolay yönetim için docker-compose kullanın. **Volume mount'lar `docker-compose.yml`'de önceden yapılandırılmıştır**:

```bash
# 1. ÖNCE kendi makinenizde çıktı dizinlerini oluşturun
mkdir -p out_download reports

# 2. Gerekirse docker-compose.yml'i düzenleyin (volume'lar zaten yapılandırılmış)
nano docker-compose.yml

# 3. Tarama çalıştırın - volume'lar otomatik olarak mevcut dizininize bağlanır
docker-compose run --rm jesur 192.168.1.0/24 -u kullanici -p sifre

# 4. Sonuçlar için yerel dizinlerinizi kontrol edin
ls -la out_download/  # İndirilen hassas dosyalar
ls -la reports/      # HTML, JSON, CSV raporları
```

**docker-compose.yml Volume Yapılandırması:**
```yaml
volumes:
  # Konteynerin /app/out_download'ını kendi makinenizdeki ./out_download'a bağlar
  - ./out_download:/app/out_download
  
  # Konteynerin /app/reports'u kendi makinenizdeki ./reports'a bağlar
  - ./reports:/app/reports
  
  # Config dosyası (salt okunur, opsiyonel)
  - ./jesur.conf:/app/jesur.conf:ro
```

**docker-compose.yml'de Özel Yollar:**
```yaml
volumes:
  # Özel konumlar için mutlak yollar kullanın
  - /home/kullanici/taramalarim/out_download:/app/out_download
  - /home/kullanici/taramalarim/reports:/app/reports
```

**Volume Mount'ları Doğrulama:**
```bash
# Hangi volume'ların bağlı olduğunu kontrol edin
docker-compose config

# Çalışan konteynerin volume'larını inceleyin
docker inspect jesur-scanner | grep -A 10 Mounts
```

**Avantajlar:**
- ✅ Python sürüm çakışmaları yok
- ✅ Bağımlılık yönetimi sorunları yok
- ✅ Sistemler arası tutarlı ortam
- ✅ Kolay temizlik (sadece konteyneri kaldırın)

**Dezavantajlar:**
- ❌ Docker kurulumu gerektirir
- ❌ Biraz daha büyük disk alanı (~500MB)

---

### Yöntem 2: Python Sanal Ortamı

Sistem genelinde Python paket kurulumundan kaçınmak isteyen kullanıcılar için önerilir.

#### Adım 1: Repository'yi Klonlayın

```bash
git clone https://github.com/cumakurt/Jesur.git
cd Jesur
```

#### Adım 2: Sanal Ortam Oluşturun

```bash
# Sanal ortam oluşturun
python3 -m venv venv

# Sanal ortamı etkinleştirin
# Linux/macOS'ta:
source venv/bin/activate

# Windows'ta:
venv\Scripts\activate
```

#### Adım 3: Pip'i Güncelleyin

```bash
pip install --upgrade pip setuptools wheel
```

#### Adım 4: Bağımlılıkları Yükleyin

```bash
pip install -r requirements.txt
```

**Kurulum süresi**: ~1-3 dakika

#### Adım 5: Kurulumu Doğrulayın

```bash
python3 Jesur.py --help
```

#### Adım 6: Çıktı Dizinlerini Oluşturun

```bash
mkdir -p out_download reports
```

#### Adım 7: İlk Taramanızı Çalıştırın

```bash
python3 Jesur.py 192.168.1.0/24 -u kullanici -p sifre
```

**Sanal ortamı deaktif etmek için:**
```bash
deactivate
```

**Avantajlar:**
- ✅ Sistem Python'undan izole
- ✅ Kaldırması kolay (sadece venv klasörünü silin)
- ✅ Root/admin erişimi gerekmez

**Dezavantajlar:**
- ❌ Python 3.7+ yüklü olmalı
- ❌ Her seferinde ortamı etkinleştirmeniz gerekir

---

### Yöntem 3: Sistem Geneli Kurulum

JESUR'u tüm kullanıcılar için sistem genelinde kurun. Admin/root erişimi gerektirir.

#### Adım 1: Repository'yi Klonlayın

```bash
git clone https://github.com/cumakurt/Jesur.git
cd Jesur
```

#### Adım 2: Sistem Bağımlılıklarını Yükleyin

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip libmagic1 libmagic-dev
```

**Linux (CentOS/RHEL):**
```bash
sudo yum install -y python3 python3-pip file-devel
```

**macOS:**
```bash
brew install python3 libmagic
```

#### Adım 3: Python Bağımlılıklarını Yükleyin

```bash
sudo pip3 install -r requirements.txt
```

**Veya sadece mevcut kullanıcı için --user bayrağını kullanın:**
```bash
pip3 install --user -r requirements.txt
```

#### Adım 4: Sembolik Bağlantı Oluşturun (Opsiyonel)

```bash
# Jesur.py'yi çalıştırılabilir yapın
chmod +x Jesur.py

# /usr/local/bin'de sembolik bağlantı oluşturun (sudo gerektirir)
sudo ln -s $(pwd)/Jesur.py /usr/local/bin/jesur

# Artık her yerden çalıştırabilirsiniz:
jesur 192.168.1.0/24 -u kullanici -p sifre
```

#### Adım 5: Kurulumu Doğrulayın

```bash
python3 Jesur.py --help
# veya sembolik bağlantı oluşturulduysa:
jesur --help
```

**Avantajlar:**
- ✅ Sistem genelinde kullanılabilir
- ✅ Herhangi bir dizinden çalıştırılabilir
- ✅ Etkinleştirme gerekmez

**Dezavantajlar:**
- ❌ Admin/root erişimi gerektirir
- ❌ Sistem Python paketleriyle çakışabilir
- ❌ Kaldırması daha zor

---

### Yöntem 4: Geliştirme Kurulumu

Kodu değiştirmek isteyen geliştiriciler için.

#### Adım 1: Repository'yi Klonlayın

```bash
git clone https://github.com/cumakurt/Jesur.git
cd Jesur
```

#### Adım 2: Sanal Ortam Oluşturun

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# veya
venv\Scripts\activate  # Windows
```

#### Adım 3: Düzenlenebilir Modda Yükleyin

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e .
```

#### Adım 4: Geliştirme Araçlarını Yükleyin (Opsiyonel)

```bash
pip install pytest pytest-cov flake8 black mypy
```

#### Adım 5: Kurulumu Doğrulayın

```bash
python3 Jesur.py --help
```

**Avantajlar:**
- ✅ Kod değişiklikleri anında yansır
- ✅ Değişiklikleri test etmek kolay
- ✅ Geliştirme araçları dahil

**Dezavantajlar:**
- ❌ Daha karmaşık kurulum
- ❌ Python geliştirme bilgisi gerektirir

---

## Kurulum Sonrası Yapılandırma

### 1. Yapılandırma Dosyası Oluşturun

```bash
# Örnek config'i kopyalayın
cp jesur.conf.example jesur.conf

# Yapılandırmayı düzenleyin
nano jesur.conf
# veya
vim jesur.conf
```

### 2. Temel Ayarları Yapılandırın

`jesur.conf` dosyasını düzenleyin:

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
exclude_ext=.log,.tmp
max_read_bytes=1048576

[output]
output_json=true
output_csv=false
quiet=false
verbose=false
```

### 3. Çıktı Dizinlerini Oluşturun

```bash
mkdir -p out_download reports
```

### 4. İzinleri Ayarlayın (Linux/macOS)

```bash
chmod 755 out_download reports
```

---

## Doğrulama

### Test 1: Yardım Komutu

```bash
# Docker
docker run --rm jesur:latest --help

# Python
python3 Jesur.py --help
```

Beklenen çıktı: Tüm mevcut seçeneklerle yardım menüsü

### Test 2: Sürüm Kontrolü

```bash
# Python sürümünü kontrol edin
python3 --version  # 3.7+ olmalı (Docker kullanıyorsanız 3.12)

# Docker sürümünü kontrol edin
docker --version  # 20.10+ olmalı
```

### Test 3: Import Testi

```bash
python3 -c "import jesur.main; import jesur.core.scanner; print('Tüm importlar başarılı')"
```

Beklenen çıktı: `Tüm importlar başarılı`

### Test 4: Paylaşım Listesi Testi

```bash
# Yerel bir IP ile test edin (test IP'nizle değiştirin)
python3 Jesur.py 127.0.0.1 -u guest -p "" --list-shares
```

Beklenen çıktı: Paylaşım listesi veya bağlantı hatası (ikisi de normal)

### Test 5: Yapılandırma Dosyası Testi

```bash
# Test config oluşturun
echo "[scan]
network=127.0.0.1" > test.conf

# Config yüklemesini test edin
python3 Jesur.py --config test.conf --list-shares
```

---

## Sorun Giderme

### Sorun 1: "python-magic" Kurulumu Başarısız

**Problem**: Linux'ta `pip install python-magic` başarısız oluyor

**Çözüm**:
```bash
# Önce sistem kütüphanesini yükleyin
sudo apt-get install libmagic1 libmagic-dev  # Debian/Ubuntu
sudo yum install file-devel  # CentOS/RHEL
brew install libmagic  # macOS

# Sonra Python paketini yükleyin
pip install python-magic
```

### Sorun 2: Docker Build Başarısız

**Problem**: Docker build ağ hatalarıyla başarısız oluyor

**Çözüm**:
```bash
# İnternet bağlantısını kontrol edin
ping google.com

# --no-cache bayrağıyla deneyin
docker build --no-cache -t jesur:latest .

# Docker daemon'u kontrol edin
sudo systemctl status docker  # Linux
```

### Sorun 3: İzin Hatası

**Problem**: Dosya yazarken izin hataları

**Çözüm**:
```bash
# Dizin izinlerini düzeltin
chmod 755 out_download reports

# Veya belirli kullanıcı ile çalıştırın (Docker)
docker run --rm --network host \
  -u $(id -u):$(id -g) \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest ...
```

### Sorun 7: Dosyalar Kendi Makinenizde Görünmüyor

**Problem**: Tarama çalıştırdınız ama bilgisayarınızda raporları/indirmeleri bulamıyorsunuz

**Çözüm**:
```bash
# 1. Volume mount'ların mevcut olduğunu doğrulayın
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest --help

# 2. Tarama çalıştırmadan ÖNCE dizinlerin var olduğunu kontrol edin
ls -la out_download/ reports/

# 3. Tarama çalıştırın ve dosyaların göründüğünü doğrulayın
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre

# 4. KENDİ yerel dizinlerinizi kontrol edin (konteyner değil)
ls -la out_download/  # İndirilen dosyaları göstermeli
ls -la reports/       # HTML, JSON, CSV dosyalarını göstermeli

# 5. Hala boşsa, volume mount sözdizimini kontrol edin
# Doğru: -v $(pwd)/out_download:/app/out_download
# Yanlış: -v out_download:/app/out_download ($(pwd)/ eksik)
```

**Yaygın Hatalar:**
```bash
# ❌ YANLIŞ - Volume mount eksik
docker run --rm --network host jesur:latest ...
# Dosyalar konteynerde kalır ve kaybolur!

# ❌ YANLIŞ - Yanlış yol sözdizimi
docker run --rm --network host \
  -v out_download:/app/out_download \
  jesur:latest ...
# $(pwd)/out_download veya mutlak yol kullanın

# ✅ DOĞRU - Uygun volume mount'lar
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest ...
```

### Sorun 4: Modül Bulunamadı Hataları

**Problem**: Çalıştırırken `ModuleNotFoundError`

**Çözüm**:
```bash
# Sanal ortamın etkinleştirildiğini doğrulayın
which python3  # venv yolunu göstermeli

# Bağımlılıkları yeniden yükleyin
pip install -r requirements.txt --force-reinstall

# Python yolunu kontrol edin
python3 -c "import sys; print('\n'.join(sys.path))"
```

### Sorun 5: Docker'da SMB Bağlantı Hataları

**Problem**: Docker konteynerinden SMB paylaşımlarına bağlanılamıyor

**Çözüm**:
```bash
# Host network modunu kullanın
docker run --rm --network host ...

# Ağ erişimini doğrulayın
docker run --rm --network host jesur:latest 192.168.1.1 -u guest -p "" --list-shares

# Güvenlik duvarı kurallarını kontrol edin
sudo iptables -L  # Linux
```

### Sorun 6: Bellek Tükenmesi Hataları

**Problem**: Konteyner veya işlem bellek tükeniyor

**Çözüm**:
```bash
# Config'de max_read_bytes'ı azaltın
max_read_bytes=512000  # 1MB yerine 512KB

# Docker belleğini sınırlayın
docker run --rm --network host --memory="512m" ...

# Thread sayısını azaltın
--threads 10  # 20+ yerine
```

---

## Kaldırma

### Docker Kurulumu

```bash
# Docker imajını kaldırın
docker rmi jesur:latest

# Konteyneri kaldırın (varsa)
docker rm jesur-scanner

# Volume'ları kaldırın (opsiyonel)
docker volume prune
```

### Sanal Ortam Kurulumu

```bash
# Ortamı deaktif edin
deactivate

# Sanal ortam dizinini kaldırın
rm -rf venv

# Klonlanmış repository'yi kaldırın (opsiyonel)
cd ..
rm -rf Jesur
```

### Sistem Geneli Kurulum

```bash
# Python paketlerini kaldırın
pip3 uninstall -r requirements.txt

# Sembolik bağlantıyı kaldırın (oluşturulduysa)
sudo rm /usr/local/bin/jesur

# Klonlanmış repository'yi kaldırın
rm -rf Jesur
```

### Tam Temizlik

```bash
# Tüm izleri kaldırın
rm -rf venv __pycache__ .pytest_cache
rm -rf out_download reports
rm -f *.html *.json *.csv *.log
rm -f jesur.conf geo_ip_cache.json
```

---

## Hızlı Referans

### Docker Hızlı Başlangıç

```bash
# Bir kez oluşturun
docker build -t jesur:latest .

# KENDİ makinenizde çıktı dizinlerini oluşturun
mkdir -p out_download reports

# Volume mount'larla tarama çalıştırın (GEREKLİ!)
# Konteynerdeki /app/out_download'a kaydedilen dosyalar → KENDİ ./out_download/ dizininizde görünür
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u kullanici -p sifre

# Dosyaların kendi makinenizde olduğunu doğrulayın
ls -la out_download/  # İndirilen dosyalar BURADA
ls -la reports/       # Raporlar BURADA
```

### Python Hızlı Başlangıç

```bash
# Kurulum
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Çalıştır
python3 Jesur.py 192.168.1.0/24 -u kullanici -p sifre
```

### Docker Compose Hızlı Başlangıç

```bash
# docker-compose.yml'i düzenleyin
nano docker-compose.yml

# Çalıştırın
docker-compose run --rm jesur 192.168.1.0/24 -u kullanici -p sifre
```

---

## Ek Kaynaklar

- **Ana Dokümantasyon**: [README.md](README.md) dosyasına bakın
- **İngilizce Dokümantasyon**: [README.md](README.md) dosyasına bakın
- **Yapılandırma Rehberi**: [jesur.conf.example](jesur.conf.example) dosyasına bakın
- **Katkıda Bulunma**: [CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bakın
- **Değişiklik Geçmişi**: [CHANGELOG.md](CHANGELOG.md) dosyasına bakın

---

## Destek

Kurulum sırasında sorun yaşarsanız:

1. Yukarıdaki [Sorun Giderme](#sorun-giderme) bölümünü kontrol edin
2. Kullanım örnekleri için [README.md](README.md) dosyasını inceleyin
3. [GitHub Issues](https://github.com/cumakurt/Jesur/issues) üzerinde bir issue açın
4. Benzer sorunlar için mevcut issue'ları kontrol edin

---

**Sürüm**: 2.0.0

