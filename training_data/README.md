# Training Данни

Тази директория е за offline ML данни и междинни артефакти.

Тя не е част от shipped desktop runtime. Rust/Tauri приложението зарежда runtime
модели от `resources/models/`, а тази папка се използва при feature extraction,
експерименти и преобучаване.

## Текуща Структура

```text
training_data/
|- features/
|  |- benign/              Извлечени benign feature JSON файлове
|  `- malware/             Извлечени malware feature JSON файлове
`- models/                 Временни обучени модели преди export или подписване
```

## Типичен Workflow

1. Извлечи features в `training_data/features/`.
2. Обучи или оцени модели с файловете от тази директория.
3. Подпиши pickle или joblib артефактите при нужда.
4. Експортирай финалния runtime модел към `resources/models/`.

Виж `python/training/README.md` за бележки относно Python инструментите.

## Важни Бележки

- Не commit-вай raw malware samples в Git.
- Дръж тук само derived features или временни training артефакти.
- Използвай законно придобити и безопасно обработвани samples за всяка работа с dataset-и.
- Ако тази директория стане голяма локално, дръж я игнорирана или я почисти преди публикуване.
