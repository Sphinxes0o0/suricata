#!/bin/bash

# Suricata 构建脚本
# 自动检测 Homebrew 安装的依赖并设置正确的路径

set -e  # 遇到错误时退出

echo "Suricata 构建脚本"
echo "=================="

# 检查是否安装了 Homebrew
if ! command -v brew &> /dev/null; then
    echo "错误: 未找到 Homebrew，请先安装 Homebrew"
    exit 1
fi

echo "检测到 Homebrew 正在查找依赖项..."

# 定义需要的依赖包
PACKAGES=("libyaml" "jansson" "pcre" "pcre2")

# 检查所有依赖是否已安装
MISSING_PACKAGES=()
for package in "${PACKAGES[@]}"; do
    if ! brew list --formula | grep -q "^${package}$"; then
        MISSING_PACKAGES+=("$package")
    fi
done

# 如果有缺失的依赖包，提示用户安装
if [ ${#MISSING_PACKAGES[@]} -ne 0 ]; then
    echo "错误: 以下依赖包未安装:"
    for package in "${MISSING_PACKAGES[@]}"; do
        echo "  - $package"
    done
    echo ""
    echo "请使用以下命令安装缺失的依赖:"
    for package in "${MISSING_PACKAGES[@]}"; do
        echo "  brew install $package"
    done
    exit 1
fi

echo "所有依赖包均已安装"

# 获取各包的前缀路径
LIBYAML_PREFIX=$(brew --prefix libyaml)
JANSSON_PREFIX=$(brew --prefix jansson)
PCRE_PREFIX=$(brew --prefix pcre)
PCRE2_PREFIX=$(brew --prefix pcre2)

echo "依赖包路径:"
echo "  libyaml: $LIBYAML_PREFIX"
echo "  jansson: $JANSSON_PREFIX"
echo "  pcre:    $PCRE_PREFIX"
echo "  pcre2:   $PCRE2_PREFIX"

# 构建 PKG_CONFIG_PATH
PKG_CONFIG_PATH="$JANSSON_PREFIX/lib/pkgconfig:$LIBYAML_PREFIX/lib/pkgconfig:$PCRE_PREFIX/lib/pkgconfig:$PCRE2_PREFIX/lib/pkgconfig"
export PKG_CONFIG_PATH

# 构建 CPPFLAGS 和 LDFLAGS
CPPFLAGS="-I$JANSSON_PREFIX/include -I$LIBYAML_PREFIX/include -I$PCRE_PREFIX/include -I$PCRE2_PREFIX/include"
LDFLAGS="-L$JANSSON_PREFIX/lib -L$LIBYAML_PREFIX/lib -L$PCRE_PREFIX/lib -L$PCRE2_PREFIX/lib"

export CPPFLAGS
export LDFLAGS

echo ""
echo "环境变量设置:"
echo "  PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
echo "  CPPFLAGS=$CPPFLAGS"
echo "  LDFLAGS=$LDFLAGS"
echo ""

# 检查是否提供了 --disable-docs 参数
DISABLE_DOCS=false
for arg in "$@"; do
    if [[ "$arg" == "--disable-docs" ]]; then
        DISABLE_DOCS=true
        break
    fi
done

# 准备 configure 参数
CONFIGURE_ARGS=()
if [[ "$DISABLE_DOCS" == true ]]; then
    CONFIGURE_ARGS+=(--disable-docs)
    echo "文档构建已禁用"
fi

# 添加其他用户提供的参数
for arg in "$@"; do
    if [[ "$arg" != "--disable-docs" ]]; then
        CONFIGURE_ARGS+=("$arg")
    fi
done

# 运行 configure
echo "运行 configure..."
echo "./configure ${CONFIGURE_ARGS[@]}"
./configure "${CONFIGURE_ARGS[@]}"

# 检查 configure 是否成功
if [ $? -eq 0 ]; then
    echo ""
    echo "Configure 成功完成！"
    echo "现在可以运行 'make' 来编译 Suricata"
    echo ""
    echo "编译命令:"
    echo "  make                    # 编译"
    echo "  make check              # 运行测试"
    echo "  sudo make install       # 安装"
else
    echo ""
    echo "Configure 失败，请检查错误信息"
    exit 1
fi