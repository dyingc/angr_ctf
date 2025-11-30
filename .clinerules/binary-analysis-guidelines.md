## Brief overview
- 针对 `ai_agent` 项目（自动化逆向 / 漏洞分析工具链）协作时的编码与沟通规范
- 重点覆盖 Python 代码、Rizin 集成、单元测试以及与 Cline 的交流风格

## Communication style
- 默认使用 **中文** 回复，非必要不掺杂英文；除非用户显式要求
- 描述力求简洁清晰；提供代码示例需 **完整可运行**
- 当外部依赖（如 Rizin）无法使用时，主动提出 mock / stub 方案并简述原因

## Development workflow
- 采用 **TDD**：先写或更新测试，再实现 / 重构功能；测试统一放在 `tests/`
- 对系统工具接口（Rizin 等）**一律使用 `unittest.mock`**，保证 CI 无外部依赖
- 新增功能需同步编写对应的 LangChain `StructuredTool` 包装器与测试
- 对长耗时或非确定性代码（线程、子进程等）添加 **超时与降级** 机制

## Coding best practices
- Python 版本以 `pyproject.toml` 为准，使用 **类型注解** 并保持 `mypy` 兼容
- 命名规范：模块 / 函数 / 变量 `snake_case`，类 `PascalCase`
- 优先使用 **f-string** 处理字符串，避免硬编码魔数
- 公共 API 返回统一结构：`{"result": …, "need_refine": …, "prompts": …}`
- 多线程 / 多进程代码须用 **全局锁** 保护 `rzpipe` 实例，防止竞态

## Testing strategies
- 测试文件命名 `test_*.py`；使用 `pytest` 或原生 `unittest` 保持风格一致
- mock 行为尽量 **还原 Rizin JSON 格式**，防止解析误差
- 针对 `StructuredTool` 包装器，校验 *包装输出 == 内部函数输出*
- 测试中避免真实 IO / 系统调用；如需文件，用 `tempfile` / `io.StringIO` 等

## Other guidelines
- 配置与常量置于 `ai_agent/config.yaml`；测试改动配置用 `monkeypatch`
- 新增脚本含 shebang（如适用）并说明可执行权限
- 若需大幅重构，先在 `plan.md` 描述设计与迁移路径，再实施代码变更
- 更新接口时同步维护 README 使用示例与依赖安装步骤
