#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DERIVED_DATA="$PROJECT_DIR/build/DerivedData"
DIST_DIR="$PROJECT_DIR/dist"
PAYLOAD_DIR="$PROJECT_DIR/build/PayloadRoot/Payload"
IPA_PATH="$DIST_DIR/CardSe-unsigned.ipa"
INTEGRITY_PATH="$DIST_DIR/CardSe-integrity.sha256"

echo "==> 正在编译 Release 版 CardSe (arm64 iOS · 符号剥离 + 硬件安全芯片绑定)..."
rm -rf "$PROJECT_DIR/build"
mkdir -p "$DIST_DIR" "$PAYLOAD_DIR"

# Remove legacy v1.x artifacts so only CardSe v2.0 artifacts remain in dist/.
rm -f "$DIST_DIR/CardVault-unsigned.ipa" "$DIST_DIR/CardVault-text.sha256"

xcodebuild \
  -project "$PROJECT_DIR/CardVault.xcodeproj" \
  -scheme CardSe \
  -configuration Release \
  -sdk iphoneos \
  -derivedDataPath "$DERIVED_DATA" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  build

APP_PATH="$DERIVED_DATA/Build/Products/Release-iphoneos/CardSe.app"
if [[ ! -d "$APP_PATH" ]]; then
  echo "错误：未找到编译产物 $APP_PATH" >&2
  exit 1
fi

cp -R "$APP_PATH" "$PAYLOAD_DIR/CardSe.app"

echo "==> 预分配 16KB 页对齐 LC_CODE_SIGNATURE 签名槽位（防止第三方自签工具破坏 __LINKEDIT）..."
/usr/bin/codesign --force --sign - --timestamp=none "$PAYLOAD_DIR/CardSe.app"

echo "==> 记录只读段完整性基线（__TEXT,__text / __const / __cstring）..."
BINARY="$PAYLOAD_DIR/CardSe.app/CardSe"
{
  for sec in __text __const __cstring; do
    hash="$(/usr/bin/otool -X -s __TEXT "$sec" "$BINARY" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
    echo "__TEXT,$sec $hash"
  done
} > "$INTEGRITY_PATH"

echo "==> 正在打包未签名 IPA..."
rm -f "$IPA_PATH"
(
  cd "$PROJECT_DIR/build/PayloadRoot"
  /usr/bin/zip -qry -X "$IPA_PATH" Payload
)

rm -rf "$PROJECT_DIR/build"
echo "==> 打包完成：$IPA_PATH"
echo "==> 段完整性指纹 ($INTEGRITY_PATH)："
/bin/cat "$INTEGRITY_PATH" | /usr/bin/sed 's/^/    /'
echo "==> 自签完成后请运行：./scripts/verify_signed_ipa.sh <已签名.ipa>"
