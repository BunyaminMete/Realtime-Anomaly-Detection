import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import random

tasks_faz2 = [
    ("Literatürdeki Çalışmalar Üzerinde Genel Karşılaştırma", "2025-02-20", "2025-03-05"),
    ("Faz 1 Sonuçlarını İyileştirme ve Model Optimizasyonu", "2025-03-06", "2025-04-10"),
    ("Gerçek Zamanlı Ağ Trafiği Analizi", "2025-03-15", "2025-05-05"),
    ("Elde Edilen Ağ Trafiğini Kullanarak Anomali Tespiti", "2025-04-01", "2025-05-15"),
    ("Model Entegrasyonu ve Anomali Tespiti", "2025-05-06", "2025-05-25"),
    ("Anomali Tespit Sisteminin Genel Testi ve İyileştirmeler", "2025-05-15", "2025-06-01"),
    ("Firebase ile Loglama ve Veri Depolama", "2025-05-20", "2025-06-07"),
    ("Mobil Uygulama Geliştirme", "2025-05-20", "2025-06-07"),
    ("Sistemin Genel Testi", "2025-05-25", "2025-06-07"),
    ("Bitirme Raporu", "2025-06-01", "2025-06-10")
]

df_faz2 = pd.DataFrame(tasks_faz2, columns=["Faaliyet", "Başlangıç", "Bitiş"])
df_faz2["Başlangıç"] = pd.to_datetime(df_faz2["Başlangıç"])
df_faz2["Bitiş"] = pd.to_datetime(df_faz2["Bitiş"])

colors = [
    "#FF5733", "#33FF57", "#3357FF", "#F39C12", "#8E44AD", 
    "#1ABC9C", "#C0392B", "#2ECC71", "#9B59B6", "#3498DB"
]
random.shuffle(colors)

df_faz2 = df_faz2[::-1]
fig, ax = plt.subplots(figsize=(12, 7))

for i, task in enumerate(df_faz2.itertuples(index=False)):
    ax.barh(task.Faaliyet, (task.Bitiş - task.Başlangıç).days, left=task.Başlangıç, color=colors[i])

ax.xaxis.grid(True, linestyle="--", linewidth=0.5)
ax.yaxis.grid(True, linestyle="--", linewidth=0.5)

ax.set_xlabel("Tarih")
ax.set_ylabel("Faaliyetler")
ax.xaxis.set_major_formatter(mdates.DateFormatter("%d-%m"))
ax.xaxis.set_major_locator(mdates.DayLocator(interval=14))

plt.xticks(rotation=45)
plt.title("Faz 2 - Güncellenmiş İş-Zaman Çizelgesi (Şubat - Haziran)")
plt.show()
