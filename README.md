# InSecurity

InSecurity е десктоп антивирусен проект с Rust/Tauri backend и React/TypeScript frontend.
Приложението комбинира сигнатурно сканиране, евристични проверки, ML оценяване чрез ONNX, репутационни справки, управление на карантина и наблюдение в реално време в десктоп среда, насочена към Windows.

## Технологичен стек

- Backend: Rust, Tauri 2, Tokio, SQLite, YARA-X
- Frontend: React 19, TypeScript, Vite, Vitest
- ML runtime: ONNX Runtime през Rust
- Offline ML инструменти: Python

## Какво Прави

- Сканира файлове с многоетапен pipeline за откриване
- Използва YARA правила, hash проверки, евристики и ML предсказания
- Поддържа бързо, пълно, персонализирано и планирано сканиране
- Следи системата в реално време за нови или променени файлове
- Поставя подозрителните файлове под карантина и проследява действията по тях
- Съхранява резултати от сканиране, обратна връзка и threat intelligence данни в SQLite
- Изтегля threat intelligence данни от MalwareBazaar
- Поддържа импорт на собствени JSON threat feed файлове към локалната база с разузнавателни данни

## Структура На Проекта

```text
.
|- src/                     Frontend React приложение
|- src-tauri/               Rust backend и Tauri приложение
|- python/                  Offline инструменти и тестове за модели
|- resources/               Модели, YARA правила и bundled данни
|- public/                  Статични frontend ресурси
|- package.json             Frontend скриптове
|- README.md
```

Основни backend модули:

- `src-tauri/src/core/pipeline.rs`: основна оркестрация на откриването
- `src-tauri/src/core/update_manager.rs`: обновяване на threat intelligence данни и импорт на feed източници
- `src-tauri/src/core/threat_feed.rs`: нормализирано парсване и мапване на threat feed записи
- `src-tauri/src/core/static_scanner.rs`: blacklist и статична логика за откриване
- `src-tauri/src/core/quarantine_manager.rs`: управление на криптирана карантина

## Разработка

Инсталиране на frontend зависимостите:

```bash
npm install
```

Стартиране само на frontend частта:

```bash
npm run dev
```

Стартиране на десктоп приложението:

```bash
npm run tauri dev
```

Проверка на Rust backend-а:

```bash
cd src-tauri
cargo check
```

## Тестване

Frontend тестове:

```bash
npm run test:run
```

TypeScript проверка:

```bash
node ./node_modules/typescript/bin/tsc --noEmit
```

Rust тестове:

```bash
cd src-tauri
cargo test --lib -- --test-threads=1
```

Тестове за Python инструментите:

```bash
python -m pytest python/tests/test_model_security.py
```

## Бележки За ML

- Runtime inference се изпълнява в Rust чрез ONNX Runtime.
- Директорията `python/` се използва за offline инструменти, подписване и тестове, свързани с моделите.
- Десктоп приложението не разчита на вграден Python runtime за inference.

## Бележки За Threat Intelligence
- Обновяването от MalwareBazaar се обработва от Rust backend-а.
- Собствени JSON feed файлове могат да бъдат нормализирани чрез `ThreatEntry` и импортирани в същите локални таблици за threat intelligence.
- Импортираните записи се отразяват и в blacklist-а, използван от статичния скенер.

Очакван JSON формат за собствен threat feed:

```json
[
  {
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "name": "AsyncRAT",
    "severity": "high",
    "family": "RAT",
    "first_seen": 1710000000
  }
]
```

## Хигиена На Хранилището

- Локални artifact папки като `tmp/` и `output/` са игнорирани.
- Build изходи като `node_modules/`, `dist/` и `target/` са игнорирани.
- Изходът от Python model-security CLI е само с ASCII символи за по-чисти логове и терминален изход.

## Бележки

- Проектът е ориентиран към Windows, защото част от детекцията и сигнатурните функции зависят от специфично за Windows поведение.
- Поддръжката за CPU emulation е по избор и се управлява чрез Rust feature-а `emulation`.
