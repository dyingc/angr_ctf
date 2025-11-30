## Brief overview
- 本指南详细说明了 `ai_agent` 项目如何使用 `uv` 工具管理 Python 依赖。
- 旨在确保开发环境的一致性、依赖安装的效率以及与 CI/CD 流程的顺畅集成。

## Development workflow
- **依赖安装与更新**:
  - 使用 `uv venv` 创建或激活虚拟环境。
  - 使用 `uv pip install -r requirements.txt` 安装项目依赖。
  - 当 `pyproject.toml` 或 `requirements.txt` 发生变化时，运行 `uv pip install -r requirements.txt` 更新依赖。
- **锁定依赖**:
  - 推荐使用 `uv pip compile` 生成 `uv.lock` 文件，以精确锁定所有依赖版本。
  - `uv pip sync` 可根据 `uv.lock` 文件安装精确版本的依赖。
- **运行测试**:
  - 激活虚拟环境后，直接运行 `pytest` 或 `python -m unittest discover`。
  - 确保所有外部依赖（如 Rizin）在测试中均被 mock，以保证 CI 环境的独立性。

## Coding best practices
- **声明依赖**:
  - 所有直接依赖应在 `pyproject.toml` 中声明。
  - 间接依赖通过 `uv pip compile` 生成的 `uv.lock` 文件管理。
- **虚拟环境**:
  - 始终在项目专用的虚拟环境中工作，避免污染系统 Python 环境。
  - 虚拟环境应位于项目根目录下的 `.venv` 文件夹中。

## Other guidelines
- **CI/CD 集成**:
  - CI 流程应首先创建或激活虚拟环境，然后使用 `uv pip install -r requirements.txt` 安装依赖。
  - 避免在 CI 中使用 `pip install`，优先使用 `uv`。
- **文档与示例**:
  - 任何涉及依赖安装的文档或示例都应明确指出使用 `uv`。
  - 对于需要特定 Rizin 版本的测试，应在测试说明中明确指出，并确保 mock 行为与该版本兼容。
