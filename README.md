# mbh_isis_authentication

v1 05.04.2021
скрипт для миграция на ISIS Hello authentication,
в три этапа без простоя связи:

1) конфигурация send-only
2) конфигурация authentication
3) удаление send-only

- проверяет есть ли KEY CHAIN
- Группа ISIS_L2_IF
- Удаляет все лишние конфиги есть ли есть ISIS_L2_IF

arguments:

- **send**:.......send-only
- **key**:........key-chain
- **nosend**:.....no-send-only
- **cfg**:........conf

