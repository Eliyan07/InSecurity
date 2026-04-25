# InSecurity

InSecurity е десктоп антивирусно приложение с многоетапна детекция на заплахи, ML класификация, проверка на цифров подпис и по избор CPU емулация за пакетирани двоични файлове.

Проектът е изграден с **Rust/Tauri 2** за backend и **React 19 + TypeScript** за frontend.

## Инсталиране С Готов Инсталатор (Windows)

Ако просто искаш да стартираш приложението, **не е нужно** да инсталираш Rust, Node.js или други инструменти за разработка.

1. Отвори страницата с готовите версии: [GitHub Releases](https://github.com/Eliyan07/InSecurity/releases)
2. Отвори **най-новия release**
3. В секцията **Assets** изтегли инсталатора за Windows
   Обикновено файлът е с име подобно на `InSecurity_1.0.1_x64-setup.exe`
4. Стартирай изтегления `.exe` файл
5. Следвай стъпките на инсталатора
6. След инсталацията отвори **InSecurity** от Start Menu или от desktop shortcut, ако е създаден

Ако искаш да компилираш проекта от source code вместо това, виж секцията **Стартиране От Source** по-долу.

## Основни Възможности

| Възможност | Описание |
|------------|----------|
| **Наблюдение в реално време** | Event-driven file watcher и process monitor за автоматично сканиране |
| **Видове сканиране** | Quick, Full, Custom и Scheduled scan режими |
| **Многоетапна детекция** | Signature -> Ingestion -> Static -> ML -> Reputation -> Novelty -> Behavior -> Emulation |
| **Проверка на цифров подпис** | Trusted signed PE файлове могат да приключат рано като clean |
| **ML класификация** | LightGBM модел, експортиран до ONNX и изпълняван през Rust ONNX Runtime с 2381 EMBER features |
| **Novelty detection** | IsolationForest модел, експортиран до ONNX и оценяващ 42 PE behavioral features |
| **Криптирана карантина** | AES-256-GCM с Argon2 key derivation |
| **Ransomware shield** | Наблюдение на protected folders, thresholds за масови промени и canary files |
| **Threat intelligence** | Hash lookup през VirusTotal, MalwareBazaar и импорт на custom JSON threat feed |
| **Audit и tamper protection** | Signed exclusions, проверка на YARA rule signatures и append-only audit log |
| **Паралелни worker-и** | Конфигурируеми 1-16 scan worker-и при ръчно сканиране |

## Pipeline За Откриване

1. **Pre-scan checks**
   Проверка за exclusions, trusted paths и ранна signature verification.
2. **Ingestion**
   Изчисляване на hashes, metadata extraction, entropy checks и basic file profiling.
3. **Static analysis**
   YARA rules, blacklist lookup и PE/header heuristics.
4. **ML classification**
   EMBER feature extraction и ONNX inference за malware probability.
5. **Reputation scoring**
   Reputation lookup по hash и допълнителни външни сигнали.
6. **Novelty detection**
   Откриване на необичайни PE поведенчески patterns чрез IsolationForest.
7. **Behavioral analysis**
   String/import patterns, suspicious API combinations и byte-level heuristics.
8. **CPU emulation**
   По избор, за packed unsigned binaries чрез Unicorn Engine.

След тези етапи се изчислява финалната оценка и се връща verdict:

- `Clean`
- `Suspicious`
- `Malware`

При открита заплаха приложението може да карантинира файла и да го запише в локалната SQLite база.

## Технологичен Стек

- Backend: Rust, Tauri 2, Tokio, SQLite, YARA-X
- Frontend: React 19, TypeScript, Vite, Vitest
- ML runtime: ONNX Runtime през Rust
- Offline ML tooling: Python

## Стартиране От Source

### Изисквания

| Зависимост | Предназначение |
|------------|----------------|
| **Rust** | Компилация на backend частта |
| **Node.js** | Frontend build и Tauri dev workflow |
| **Visual Studio Build Tools** | Полезни за Windows native builds |
| **LLVM/Clang + CMake** | Нужни само ако ще се компилира с `--features emulation` |
| **Python** | По избор, само за offline ML tooling и Python-side тестове |

Важно:

- Python не е нужен за runtime сканиране.
- ONNX моделите и YARA ресурсите вече са налични в `resources/`.
- Старото описание с bundled Python runtime и conversion scripts вече не е актуално за този вариант на проекта.

### Инсталация И Стартиране

Инсталиране на frontend зависимостите:

```bash
npm install
```

Стартиране на приложението в dev режим:

```bash
npm run tauri dev
```

Production build:

```bash
npm run tauri build
```

Ако искаш build с CPU емулация:

```bash
cd src-tauri
cargo build --features emulation
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

Optional Python tooling tests:

```bash
python -m pytest python/tests/test_model_security.py
```

## Структура На Проекта

```text
.
|- src/                     React frontend
|- src-tauri/               Rust backend и Tauri приложение
|- python/                  Offline ML tooling
|- training_data/           Training features и междинни model artifacts
|- resources/               ONNX модели, YARA правила, whitelists и помощни ресурси
|- public/                  Статични frontend assets
|- package.json
`- README.md
```

Ключови backend файлове:

- `src-tauri/src/core/pipeline.rs` - основен detection pipeline
- `src-tauri/src/core/update_manager.rs` - threat intelligence updates и feed ingestion
- `src-tauri/src/core/threat_feed.rs` - нормализация на custom threat feed записи
- `src-tauri/src/core/quarantine_manager.rs` - криптирана карантина
- `src-tauri/src/core/tamper_protection.rs` - audit log и tamper-evident защита
- `src-tauri/src/core/real_time.rs` - real-time protection и ransomware monitoring
- `src-tauri/src/ml/onnx_classifier.rs` - ONNX classifier inference
- `src-tauri/src/ml/onnx_novelty.rs` - ONNX novelty detector inference

## ML И Сигурност

### Classifier

- Използва 2381 EMBER features
- Работи през `resources/models/classifier/model.onnx`
- Прагове по подразбиране: `0.90` за malware и `0.35` за suspicious

### Novelty Detector

- Използва 42 behavioral PE features
- Работи през `resources/models/novelty/model.onnx`
- Допълва класическия classifier с аномалийно откриване

### Quarantine И Integrity

- Карантината използва AES-256-GCM
- Ключът се извежда чрез Argon2 или се държи през OS keyring/file fallback
- Exclusions и audit events се подписват за tamper evidence
- YARA rule signatures се валидират при зареждане

## Допълнителни Бележки

- Проектът е ориентиран основно към Windows.
- Част от signature verification, trusted path logic, autostart и network monitoring са Windows-specific.
- `python/` е помощна директория за offline model tooling, а не част от основния runtime.
- Наличието на `resources/python_runtime/` е legacy остатък от по-стар packaging подход, но текущите build-ове не разчитат на него за runtime inference.
- `training_data/` е за експерименти и междинни training артефакти, не за production runtime.
