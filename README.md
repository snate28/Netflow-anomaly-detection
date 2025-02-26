# Netflow-anomaly-detection
The script collects netflow data to train a neural network to detect its anomalies. Once the model is trained, model continuously monitors netflow traffic and reports anomalies.

Для работы библиотеки scapy возможно придется установить wincap https://www.winpcap.org/install/ или ncap https://npcap.com/

При запуске assignment.py программа сначала проверяет наличие готовой модели. Если модели нет, то программа начнет собирать пакеты в течении 24 часов ( можно поставить другую продолжительность, поменяв значение переменной TRAINING_DURATION ). Затем модель будет обучаться на собранных данных. После того, как модель обучилась, она сохранится в файле flow_autoencoder.h5 и программа начнет мониторить пакеты и каждую минуту ( можно поставить другой период, поменяв значение переменной TEST_WINDOW) давать отчет об аномальных пакетах и записывать их в файл anomaly_report, который создасться в той же директории, где запущен assignment.py, также в этой директории будут XLS файлы test_flows(непрерывный мониторинг) и training_flows(пакеты, на которых тренировалась модель). Если же при запуске assignment.py в директории уже есть готовая модель flow_autoencoder.h5, то программа сразу начнет мониторить аномалии, основываясь на этой модели. 
Файл "example_of_anomaly_report" содержит пример отчета аномальной сетевой активности. 
