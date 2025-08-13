
## Engine initialization

```python
engine = EngineConfigurator()
    .add_ini_routine(...)
    .add_ini_routine(...)
    .add_fini_routine(...)
    .add_fini_routine(...)
    .add_fini_routine(...)
    .add_hook(...)
    .add_hook(...)

engine.emulate_until_ret(0x100000)
engine.emulate_range(0x1000, 0x2000)
```
