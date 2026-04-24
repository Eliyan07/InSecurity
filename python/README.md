# Python Инструменти

Тази директория е само за offline инструменти за разработка.

Готовото десктоп приложение не използва Python по време на работа. Детекцията,
сканирането и защитата в реално време се изпълняват в Rust, а пакетираното
приложение включва ONNX модели и други ресурси вместо Python runtime.

## За Какво Се Използва Тази Папка

- обучение или оценяване на ML модели
- извличане на training features от PE файлове
- подписване и проверка на pickle или joblib model артефакти
- изпълнение на Python тестове за инструментите

## За Какво Не Се Използва Тази Папка

- runtime сканиране
- frontend или backend логика на приложението
- защита в реално време
- bundled production зависимости

## Основни Файлове

- `ml_models/model_security.py`: подписва и проверява offline model артефакти
- `training/extract_features.py`: извлича training features от PE файлове
- `training/train_novelty.py`: обучава novelty-detection модела
- `tests/test_model_security.py`: валидира Python helper функциите за подписване на модели

## За GitHub Преглеждащи

Ако разглеждаш самото десктоп приложение, основният runtime код е в:

- `src-tauri/`
- `src/`
- `resources/models/`

Тази Python директория е допълнителен набор от инструменти за workflow-а по разработка на модели.
