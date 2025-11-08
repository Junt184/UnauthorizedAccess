"""集中管理靶场各关卡的 flag。

说明：
- 为了便于维护与复用，将关卡涉及的 flag 常量统一放在项目根目录下的 flags.py。
- 各关卡通过 `from flags import ...` 进行导入使用。
"""

LEVEL1_AFTER_FLAG = "flag{level1_overwrite_registration_success}"

# 如需新增更多关卡或更多 flag，请在此补充相应常量，例如：
# LEVEL2_INDEX_FLAG = "flag{level2_example}"
LEVEL2_AFTER_FLAG = "flag{level2_passed}"