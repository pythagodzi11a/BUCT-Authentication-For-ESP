# Auth
一个用来实现BUCT小愿望认证的库，基于ArduinoHttpClient。

# 依赖
- ArduinoHttpClient
- Arduino
- WiFi

# 使用
只有两个方法：
- `std::pair<bool, String> isOnline();`：检查当前认证状态。
- `std::pair<bool, String> login(const String &username,
                                  const String &password,
                                  const String &system = "Windows 95");`：进行认证，参数分别是用户名、密码和系统类型（默认是Windows 95）。返回值是一个pair，第一个元素表示认证是否成功，第二个元素是服务器返回的消息。

# License
- MIT（见仓库根目录 `LICENSE`）
