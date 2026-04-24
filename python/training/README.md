# Бележки За Python Training

Тази папка съдържа незадължителни скриптове за offline ML експерименти.

Production приложението не изпълнява тези скриптове. Те съществуват, за да може
хранилището да възпроизвежда или развива своите ML assets извън shipped Rust runtime.

## Включени Скриптове

- `extract_features.py`
  Извлича training features от PE файлове и ги записва в JSON.

- `train_novelty.py`
  Обучава novelty detector-а от подготвени feature набори и записва model
  артефакти за по-късен export или подписване.

## Типичен Workflow

1. Събери benign PE samples за обучение.
2. Стартирай `extract_features.py` върху тези samples.
3. Обучи novelty модел с `train_novelty.py`.
4. Подпиши генерираните pickle/joblib артефакти с `ml_models/model_security.py`.
5. Експортирай или обнови финалните runtime model assets, използвани от Rust приложението.

## Важен Контекст

- Това са само offline инструменти.
- Runtime inference в десктоп приложението използва Rust и ONNX модели.
- Ако не преобучаваш модели, тази папка не ти е нужна, за да build-неш или стартираш приложението.
