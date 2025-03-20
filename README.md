# NetGuard Pro - Advanced Network Security Tool

[English](#english) | [Türkçe](#türkçe)

## English

NetGuard Pro is a powerful and professional network security tool designed for network administrators, security professionals, and educational purposes. It provides comprehensive network analysis, security assessment, and traffic monitoring capabilities.

### Why NetGuard Pro?

NetGuard Pro offers several advantages over traditional tools like ettercap and bettercap:

1. User Interface:
   - Modern GUI interface with dark theme
   - Intuitive controls and real-time feedback
   - No command-line knowledge required
   - Visual progress tracking and results display

2. Performance:
   - Faster scanning with optimized algorithms
   - Asynchronous operations for better responsiveness
   - Multi-threaded architecture
   - Lower resource usage compared to ettercap/bettercap

3. Features:
   - More comprehensive security analysis
   - Built-in SSL/TLS certificate inspection
   - Website security assessment
   - DNS and WHOIS analysis
   - Real-time traffic monitoring
   - Detailed logging and reporting

4. Ease of Use:
   - One-click scanning options
   - Automatic interface detection
   - Built-in help and documentation
   - Cross-platform compatibility

5. Safety:
   - Built-in safety checks
   - Automatic backup of network settings
   - Warning system for potentially dangerous operations
   - No risk of network disruption

### Comparison with Other Tools

| Feature | NetGuard Pro | ettercap | bettercap |
|---------|--------------|-----------|-----------|
| GUI Interface | ✅ Modern, Dark Theme | ❌ CLI Only | ❌ CLI Only |
| Performance | ✅ Fast & Optimized | ⚠️ Moderate | ⚠️ Moderate |
| Resource Usage | ✅ Low | ⚠️ High | ⚠️ High |
| SSL/TLS Analysis | ✅ Built-in | ❌ Requires Plugins | ❌ Requires Plugins |
| Website Security | ✅ Built-in | ❌ No | ❌ No |
| DNS Analysis | ✅ Built-in | ❌ No | ❌ No |
| WHOIS Lookup | ✅ Built-in | ❌ No | ❌ No |
| Real-time Monitoring | ✅ Advanced | ⚠️ Basic | ⚠️ Basic |
| User-Friendliness | ✅ Very High | ⚠️ Moderate | ⚠️ Moderate |
| Safety Features | ✅ Comprehensive | ⚠️ Basic | ⚠️ Basic |
| Cross-Platform | ✅ Yes | ⚠️ Limited | ⚠️ Limited |

### Features

- Modern GUI interface with dark theme
- Multiple scanning modes:
  - Quick Scan: Fast port and service detection
  - Deep Scan: Comprehensive system analysis
  - Vulnerability Scan: Security vulnerability assessment
- Advanced capabilities:
  - SSL/TLS certificate analysis
  - Website security assessment
  - DNS record analysis
  - WHOIS information gathering
  - Real-time traffic monitoring
  - ARP scanning
  - Port scanning with service detection
  - Vulnerability detection
  - Detailed logging and reporting

### Requirements

- Python 3.8 or higher
- Administrator/Root privileges (for some features)
- Npcap or WinPcap (for Windows)
- Required Python packages (install using `pip install -r requirements.txt`)

### Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/netguard-pro.git
cd netguard-pro
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install Npcap (Windows):
   - Download from: https://npcap.com/#download
   - Run the installer
   - Select "Install Npcap in WinPcap API-compatible Mode"
   - Restart your computer

### Usage

#### GUI Mode
```bash
python network_security_tool.py --gui
```

#### Command Line Mode
```bash
python network_security_tool.py -t 192.168.1.0/24 -m quick
```

Options:
- `-t` or `--target`: Target IP or network
- `-m` or `--mode`: Scan mode (quick, deep, or vuln)
- `-i` or `--interface`: Network interface
- `--gui`: Launch GUI interface

### Features in Detail

1. Network Scanning
   - Fast ARP scanning
   - Port scanning with service detection
   - OS fingerprinting
   - Service version detection

2. Security Analysis
   - SSL/TLS certificate inspection
   - Website security headers analysis
   - DNS record analysis
   - WHOIS information gathering

3. Traffic Monitoring
   - Real-time network traffic analysis
   - Protocol analysis
   - Packet size monitoring
   - Source and destination tracking

4. Reporting
   - Detailed logging
   - Scan results export
   - Vulnerability reports
   - Traffic statistics

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### License

This project is licensed under the MIT License - see the LICENSE file for details.

### Disclaimer

This tool is for educational and testing purposes only. Always obtain proper authorization before testing on any network.

---

## Türkçe

NetGuard Pro, ağ yöneticileri, güvenlik uzmanları ve eğitim amaçları için tasarlanmış güçlü ve profesyonel bir ağ güvenlik aracıdır. Kapsamlı ağ analizi, güvenlik değerlendirmesi ve trafik izleme özellikleri sunar.

### Neden NetGuard Pro?

NetGuard Pro, ettercap ve bettercap gibi geleneksel araçlara göre birçok avantaj sunar:

1. Kullanıcı Arayüzü:
   - Koyu temalı modern GUI arayüzü
   - Sezgisel kontroller ve gerçek zamanlı geri bildirim
   - Komut satırı bilgisi gerektirmez
   - Görsel ilerleme takibi ve sonuç gösterimi

2. Performans:
   - Optimize edilmiş algoritmalarla daha hızlı tarama
   - Daha iyi yanıt için asenkron işlemler
   - Çoklu iş parçacığı mimarisi
   - ettercap/bettercap'a göre daha düşük kaynak kullanımı

3. Özellikler:
   - Daha kapsamlı güvenlik analizi
   - Dahili SSL/TLS sertifika inceleme
   - Website güvenlik değerlendirmesi
   - DNS ve WHOIS analizi
   - Gerçek zamanlı trafik izleme
   - Detaylı loglama ve raporlama

4. Kullanım Kolaylığı:
   - Tek tıkla tarama seçenekleri
   - Otomatik arayüz tespiti
   - Dahili yardım ve dokümantasyon
   - Platformlar arası uyumluluk

5. Güvenlik:
   - Dahili güvenlik kontrolleri
   - Ağ ayarlarının otomatik yedeklenmesi
   - Potansiyel tehlikeli işlemler için uyarı sistemi
   - Ağ kesintisi riski yok

### Diğer Araçlarla Karşılaştırma

| Özellik | NetGuard Pro | ettercap | bettercap |
|---------|--------------|-----------|-----------|
| GUI Arayüzü | ✅ Modern, Koyu Tema | ❌ Sadece CLI | ❌ Sadece CLI |
| Performans | ✅ Hızlı & Optimize | ⚠️ Orta | ⚠️ Orta |
| Kaynak Kullanımı | ✅ Düşük | ⚠️ Yüksek | ⚠️ Yüksek |
| SSL/TLS Analizi | ✅ Dahili | ❌ Eklenti Gerekli | ❌ Eklenti Gerekli |
| Website Güvenliği | ✅ Dahili | ❌ Yok | ❌ Yok |
| DNS Analizi | ✅ Dahili | ❌ Yok | ❌ Yok |
| WHOIS Sorgulama | ✅ Dahili | ❌ Yok | ❌ Yok |
| Gerçek Zamanlı İzleme | ✅ Gelişmiş | ⚠️ Temel | ⚠️ Temel |
| Kullanıcı Dostu | ✅ Çok Yüksek | ⚠️ Orta | ⚠️ Orta |
| Güvenlik Özellikleri | ✅ Kapsamlı | ⚠️ Temel | ⚠️ Temel |
| Platform Uyumluluğu | ✅ Var | ⚠️ Sınırlı | ⚠️ Sınırlı |

### Özellikler

- Koyu temalı modern GUI arayüzü
- Çoklu tarama modları:
  - Hızlı Tarama: Port ve servis tespiti
  - Derin Tarama: Kapsamlı sistem analizi
  - Güvenlik Açığı Taraması: Güvenlik değerlendirmesi
- Gelişmiş özellikler:
  - SSL/TLS sertifika analizi
  - Website güvenlik değerlendirmesi
  - DNS kayıt analizi
  - WHOIS bilgi toplama
  - Gerçek zamanlı trafik izleme
  - ARP tarama
  - Servis tespitli port tarama
  - Güvenlik açığı tespiti
  - Detaylı loglama ve raporlama

### Gereksinimler

- Python 3.8 veya üzeri
- Yönetici/Root yetkisi (bazı özellikler için)
- Npcap veya WinPcap (Windows için)
- Gerekli Python paketleri (`pip install -r requirements.txt` ile yükleyin)

### Kurulum

1. Depoyu klonlayın:
```bash
git clone https://github.com/yourusername/netguard-pro.git
cd netguard-pro
```

2. Bağımlılıkları yükleyin:
```bash
pip install -r requirements.txt
```

3. Npcap'i yükleyin (Windows):
   - https://npcap.com/#download adresinden indirin
   - Kurulum dosyasını çalıştırın
   - "Install Npcap in WinPcap API-compatible Mode" seçeneğini işaretleyin
   - Bilgisayarınızı yeniden başlatın

### Kullanım

#### GUI Modu
```bash
python network_security_tool.py --gui
```

#### Komut Satırı Modu
```bash
python network_security_tool.py -t 192.168.1.0/24 -m quick
```

Seçenekler:
- `-t` veya `--target`: Hedef IP veya ağ
- `-m` veya `--mode`: Tarama modu (quick, deep, vuln)
- `-i` veya `--interface`: Ağ arayüzü
- `--gui`: GUI arayüzünü başlat

### Detaylı Özellikler

1. Ağ Tarama
   - Hızlı ARP tarama
   - Servis tespitli port tarama
   - İşletim sistemi tespiti
   - Servis versiyon tespiti

2. Güvenlik Analizi
   - SSL/TLS sertifika inceleme
   - Website güvenlik başlıkları analizi
   - DNS kayıt analizi
   - WHOIS bilgi toplama

3. Trafik İzleme
   - Gerçek zamanlı ağ trafiği analizi
   - Protokol analizi
   - Paket boyutu izleme
   - Kaynak ve hedef takibi

4. Raporlama
   - Detaylı loglama
   - Tarama sonuçları dışa aktarma
   - Güvenlik açığı raporları
   - Trafik istatistikleri

### Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen Pull Request göndermekten çekinmeyin.

### Lisans

Bu proje MIT Lisansı altında lisanslanmıştır - detaylar için LICENSE dosyasına bakın.

### Sorumluluk Reddi

Bu araç sadece eğitim ve test amaçlıdır. Herhangi bir ağda test yapmadan önce gerekli yetkilendirmeyi aldığınızdan emin olun. 