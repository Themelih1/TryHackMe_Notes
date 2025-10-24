# 🛡️ Siber Güvenlik - Defansif Güvenlik Ders Notları

## 📋 İçindekiler
- [Defansif Güvenlik Temelleri](#1-defansif-güvenlik-temelleri)
- [Rate Limiting](#2-rate-limiting)
- [WAF](#3-waf-web-application-firewall)
- [SQL Injection](#4-sql-injection--test-yöntemleri)
- [Yasal ve Etik Kurallar](#5-yasal-ve-etik-kurallar)
- [SOC](#6-soc-security-operations-center)
- [Pratik Komutlar](#7-pratik-komutlar-ve-araclar)
- [Önemli Kavramlar](#8-önemli-kavramlar)
- [Best Practices](#9-best-practices)

---

## 1. Defansif Güvenlik Temelleri

### 1.1 Defansif Güvenlik Nedir?
- **Amaç**: Sistemleri proaktif olarak koruma
- **Yaklaşım**: Katmanlı savunma (Defence in Depth)

### 1.2 Takım Rolleri
| Rol | Görev | Konum |
|-----|-------|-------|
| **SOC Analisti** | Alarm izleme, ilk tespit | Ön cephe |
| **Olay Müdahale** | Aktif saldırı engelleme | İkinci hat |
| **Güvenlik Mühendisi** | Savunma araçları geliştirme | Arka plan |
| **Dijital Adli Analist** | Olay sonrası inceleme | Analiz |

### 1.3 Savunma Katmanları

    Katman: Çalışan Eğitimi → İnsan faktörü

    Katman: IDS/IPS → Ağ izleme

    Katman: Firewall → Trafik filtresi

    Katman: Güvenlik Politikaları → Kurallar

text


---

## 2. Rate Limiting

### 2.1 Nedir?
- Belirli zaman aralığında maksimum istek sayısı sınırı
- **Amaç**: Brute force, DDoS koruması

### 2.2 Uygulama Yöntemleri

#### Nginx Örneği
```nginx
http {
    limit_req_zone $binary_remote_addr zone=admin:10m rate=10r/m;
    
    server {
        location /admin/ {
            limit_req zone=admin burst=20 nodelay;
            limit_req_status 429;
        }
    }
}

Node.js Örneği
javascript

const rateLimit = require('express-rate-limit');

const adminLimiter = rateLimit({
    windowMs: 60 * 1000,    // 1 dakika
    max: 10,                // 10 istek
    message: 'Too many requests',
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/admin', adminLimiter);

2.3 Önerilen Limitler
Endpoint	Zaman	Maks İstek	Açıklama
Admin Login	60sn	5	Sıkı koruma
API Endpoint	60sn	30	Orta koruma
Static Dosya	60sn	100	Geniş koruma
3. WAF (Web Application Firewall)
3.1 WAF Nedir?

    Web uygulamaları önünde güvenlik filtresi

    Çalışma Mantığı: İstek → WAF Filtresi → Uygulama

3.2 Engellediği Saldırılar

    ✅ SQL Injection

    ✅ XSS (Cross-Site Scripting)

    ✅ Path Traversal

    ✅ File Inclusion

    ✅ Brute Force

3.3 WAF Kural Örnekleri
AWS WAF Kuralı
json

{
  "Name": "Block-SQL-Injection",
  "Priority": 5,
  "Statement": {
    "ByteMatchStatement": {
      "FieldToMatch": {"Body": {}},
      "PositionalConstraint": "CONTAINS",
      "SearchString": "union select"
    }
  },
  "Action": {"Block": {}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "Block-SQL-Injection"
  }
}

ModSecurity Kuralı
apache

SecRule REQUEST_FILENAME|ARGS|REQUEST_BODY "@detectSQLi" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'SQL Injection Attack Detected',\
    severity:'CRITICAL'"

4. SQL Injection & Test Yöntemleri
4.1 SQL Injection Nedir?

    Kötü niyetli SQL kodu enjeksiyonu

    Hedef: Veritabanını manipüle etme

4.2 GET Metodu ile Test
text

Normal:   https://site.com/urun?id=1
Injection: https://site.com/urun?id=1' OR '1'='1

4.3 Temel Test Payload'ları
sql

-- Authentication Bypass
' OR '1'='1
admin' --

-- Union-Based
' UNION SELECT 1,2,3 --

-- Error-Based  
' AND (SELECT 1 FROM (SELECT COUNT(*)...)) --

-- Time-Based
' AND SLEEP(5) --

4.4 SQLMap Kullanımı
bash

# Temel tarama
sqlmap -u "http://site.com/page?id=1"

# Detaylı tarama
sqlmap -u "http://site.com/page?id=1" --dbs --tables

# WAF bypass
sqlmap -u "http://site.com/page?id=1" --random-agent --delay=2

# Parametre bulma
sqlmap -u "http://site.com" --crawl=2 --forms

5. Yasal ve Etik Kurallar
5.1 KESİNLİKLE YAPILMAYACAKLAR

    ❌ İzinsiz sistem testi

    ❌ Canlı sitelerde saldırı

    ❌ Kötü niyetli kullanım

5.2 GÜVENLİ TEST ORTAMLARI
bash

# DVWA Kurulumu
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Test URL'si
http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit

5.3 Legal Platformlar

    TryHackMe.com

    HackTheBox.com

    OverTheWire.org

    VulnHub.com

5.4 Sorumlu Açıklık Bildirimi

    ✅ Site sahibine bildirme

    ✅ Detaylı rapor hazırlama

    ✅ Düzeltme süresi tanıma

    ❌ Hemen açıklama yapmama

6. SOC (Security Operations Center)
6.1 SOC Görevleri

    🔍 Alarmları inceleme

    🔍 Anomalileri araştırma

    🔍 Olaylara müdahale etme

6.2 SIEM Sistemleri

    Görev: Tüm güvenlik verilerini merkezileştirme

    Benzetme: Siber güvenlik radarı

    Fayda: Hızlı analiz ve korelasyon

7. Pratik Komutlar ve Araçlar
7.1 SQLMap Hata Çözümleri
bash

# 403 Hatası Çözümü
sqlmap -u "URL" --random-agent --proxy="http://127.0.0.1:8080"

# Güncelleme
sudo sqlmap --update

# Cookie ile test
sqlmap -u "http://site.com/page" --cookie="session=abc123"

7.2 Rate Limiting Test
bash

# Rate Limit Testi
curl -X POST http://site.com/login \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Çoklu İstek Testi
for i in {1..15}; do curl http://site.com/admin; done

7.3 HTTP Status Kodları

    200: Başarılı

    403: Yasaklı (WAF engeli)

    404: Bulunamadı

    429: Çok Fazla İstek (Rate Limit)

    500: Sunucu Hatası

8. Önemli Kavramlar
8.1 HTTP Metodları
Method	Açıklama	Kullanım
GET	URL'den veri gönderme	SQL injection için uygun
POST	Body'den veri gönderme	Form submission
PUT	Veri güncelleme	API requests
DELETE	Veri silme	API requests
8.2 Güvenlik Terimleri
Terim	Açıklama
WAF	Web Uygulama Güvenlik Duvarı
IDS/IPS	Saldırı Tespit/Önleme Sistemi
SIEM	Güvenlik Bilgi ve Olay Yönetimi
SOC	Güvenlik Operasyon Merkezi
9. Best Practices
9.1 Güvenlik Öncelikleri

    Proaktif ol → Reactive olma

    Katmanlı koruma → Tek noktaya güvenme

    Sürekli izle → Aralıklı kontrol etme

    Güncel tut → Eski yazılım kullanma

9.2 Test Stratejisi

    Önce izle → Trafiği anla

    Test et → Lab ortamında dene

    Kademeli uygula → Aniden geçme

    Monitor et → Sürekli izle

9.3 Defansif Mindset

    "Nasıl saldırılır?" değil, "Nasıl korunur?" düşün

    Sürekli öğrenme ve güncelleme

    Topluluk ve paylaşım önemli

🔐 Özet ve Sonuç
🎯 Anahtar Çıkarımlar

    Defansif güvenlik = Proaktif koruma

    Rate limiting = Brute force koruması

    WAF = Web uygulama filtresi

    SQL injection = Veritabanı saldırısı

    Yasal etik = İzinsiz test yapılmaz

⚠️ Unutulmaması Gerekenler

    Bilgi güvenliği için kullanılır, güvenliği ihlal etmek için değil!

    Kendi lab ortamında pratik yap

    Sürekli öğren ve güncel kal

🚀 Sonraki Adımlar

    DVWA kur ve pratik yap

    TryHackMe platformunda başla

    Güvenlik bloglarını takip et

    Topluluklara katıl

📚 Kaynaklar

    OWASP Top 10

    SQLMap Documentation

    DVWA GitHub

    Not: Bu doküman eğitim amaçlı hazırlanmıştır. Tüm siber güvenlik aktiviteleri yasal sınırlar içinde yapılmalıdır.

Son güncelleme: ${new Date().toLocaleDateString()}
