#!/bin/zsh
# CardSe v2.0 — 签名后 IPA 深度完整性、注入、零同步权限与段哈希检查
# 用法：./scripts/verify_signed_ipa.sh /path/to/已签名.ipa
set -euo pipefail

if [[ $# -ne 1 || ! -f "$1" ]]; then
  echo "用法：$0 /path/to/signed.ipa" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INTEGRITY_FILE="$PROJECT_DIR/dist/CardSe-integrity.sha256"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
/usr/bin/unzip -q "$1" -d "$WORK_DIR"

if [[ ! -d "$WORK_DIR/Payload" ]]; then
  echo "❌ IPA 缺少 Payload 目录" >&2
  exit 1
fi

APP_COUNT="$(/usr/bin/find "$WORK_DIR/Payload" -maxdepth 1 -name '*.app' -type d | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
if [[ "$APP_COUNT" -ne 1 ]]; then
  echo "❌ Payload 内 .app 数量异常（$APP_COUNT 个）" >&2
  exit 1
fi

APP_DIR="$(/usr/bin/find "$WORK_DIR/Payload" -maxdepth 1 -name '*.app' -type d | /usr/bin/head -n 1)"
PLIST="$APP_DIR/Info.plist"
if [[ ! -f "$PLIST" ]]; then
  echo "❌ 缺少 Info.plist" >&2
  exit 1
fi

EXECUTABLE="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$PLIST" 2>/dev/null || true)"
if [[ -z "$EXECUTABLE" || "$EXECUTABLE" == *"/"* || "$EXECUTABLE" == *".."* ]]; then
  echo "❌ CFBundleExecutable 非法（疑似路径穿越篡改）：$EXECUTABLE" >&2
  exit 1
fi

BINARY="$APP_DIR/$EXECUTABLE"
if [[ ! -f "$BINARY" ]]; then
  echo "❌ 找不到主程序二进制：$BINARY" >&2
  exit 1
fi

failed=0
warned=0

echo "== 1. 架构与符号链接检查 =="
archs="$(/usr/bin/lipo -archs "$BINARY" 2>/dev/null || true)"
if [[ "$archs" != "arm64" ]]; then
  echo "❌ Mach-O 架构异常（期望单一 arm64，实际：$archs，警惕胖二进制夹带切片）"
  failed=1
else
  echo "✅ 单一 arm64 架构"
fi

symlinks="$(/usr/bin/find "$APP_DIR" -type l)"
if [[ -n "$symlinks" ]]; then
  echo "❌ 包内存在可疑符号链接：$symlinks"
  failed=1
else
  echo "✅ 无符号链接"
fi

echo "== 2. Mach-O 动态库加载命令全量检查 =="
dylib_count=0
bad_dylib=0
while IFS= read -r dylib_line; do
  [[ -z "$dylib_line" ]] && continue
  dylib_count=$((dylib_count + 1))
  case "$dylib_line" in
    /System/Library/*|/usr/lib/*) ;;
    *)
      echo "❌ 发现非系统动态库加载命令：$dylib_line（疑似签名工具注入）"
      bad_dylib=1
      failed=1
      ;;
  esac
done < <(/usr/bin/otool -l "$BINARY" | /usr/bin/awk '
  /cmd LC_(LOAD_DYLIB|LOAD_WEAK_DYLIB|REEXPORT_DYLIB|LAZY_LOAD_DYLIB|UPWARD_DYLIB)/ { in_dylib=1; next }
  in_dylib && /^[[:space:]]*name / {
    sub(/^[[:space:]]*name /, "");
    sub(/ \(offset [0-9]+\)$/, "");
    print;
    in_dylib=0
  }
')
[[ $bad_dylib -eq 0 ]] && echo "✅ 仅加载 iOS 系统动态库（共 $dylib_count 项）"

echo "== 3. 包内文件严格白名单检查 =="
extra=0
while IFS= read -r rel; do
  case "$rel" in
    "$EXECUTABLE"|Info.plist|PkgInfo|Assets.car|AppIcon60x60@2x.png|AppIcon60x60@3x.png|AppIcon76x76@2x~ipad.png|embedded.mobileprovision|_CodeSignature|_CodeSignature/CodeResources|SC_Info|SC_Info/Manifest.plist) ;;
    *)
      echo "❌ 发现原始构建之外的可疑文件：$rel"
      extra=1
      failed=1
      ;;
  esac
done < <(cd "$APP_DIR" && /usr/bin/find . -mindepth 1 | /usr/bin/sed 's|^\./||')
[[ $extra -eq 0 ]] && echo "✅ 包内无多余 dylib / framework / 插件或隐藏载荷"

echo "== 4. Info.plist 断网与隐私配置检查 =="
file_sharing="$(/usr/libexec/PlistBuddy -c 'Print :UIFileSharingEnabled' "$PLIST" 2>/dev/null || echo 'missing')"
open_in_place="$(/usr/libexec/PlistBuddy -c 'Print :LSSupportsOpeningDocumentsInPlace' "$PLIST" 2>/dev/null || echo 'missing')"
ats_arbitrary="$(/usr/libexec/PlistBuddy -c 'Print :NSAppTransportSecurity:NSAllowsArbitraryLoads' "$PLIST" 2>/dev/null || echo 'missing')"
scene_delegate="$(/usr/libexec/PlistBuddy -c 'Print :UIApplicationSceneManifest:UISceneConfigurations:UIWindowSceneSessionRoleApplication:0:UISceneDelegateClassName' "$PLIST" 2>/dev/null || echo '')"
url_types="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleURLTypes' "$PLIST" 2>/dev/null || true)"

if [[ "$file_sharing" != "false" || "$open_in_place" != "false" || "$ats_arbitrary" != "false" || -z "$scene_delegate" || -n "$url_types" ]]; then
  echo "❌ Info.plist 安全或生命周期配置异常（UIFileSharingEnabled=$file_sharing, OpenInPlace=$open_in_place, ATSArbitrary=$ats_arbitrary, SceneDelegate=$scene_delegate）"
  failed=1
else
  echo "✅ Info.plist 隔离与 UIScene 生命周期配置完整（SceneDelegate=$scene_delegate）"
fi

echo "== 5. Mach-O 多段只读数据完整性检查 =="
if [[ -f "$INTEGRITY_FILE" ]]; then
  sec_mismatch=0
  while IFS=' ' read -r section expected_hash; do
    [[ -z "$section" ]] && continue
    seg="${section%,*}"
    sec="${section#*,}"
    actual_hash="$(/usr/bin/otool -X -s "$seg" "$sec" "$BINARY" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
    if [[ "$actual_hash" != "$expected_hash" ]]; then
      echo "❌ 段 $section 哈希不一致（期望 $expected_hash，实际 $actual_hash）"
      sec_mismatch=1
      failed=1
    fi
  done < "$INTEGRITY_FILE"
  [[ $sec_mismatch -eq 0 ]] && echo "✅ __TEXT,__text / __const / __cstring 与原始编译产物 100% 一致"
else
  echo "⚠️  未找到 $INTEGRITY_FILE，跳过段比对（请先运行 ./scripts/build_ipa.sh）"
  warned=1
fi

echo "== 6. 代码签名与零同步权限（Entitlements）检查 =="
if /usr/bin/codesign --verify --deep --strict "$APP_DIR" 2>/dev/null; then
  echo "✅ codesign 数字签名结构校验通过"
  entitlements="$(/usr/bin/codesign -d --entitlements - --xml "$APP_DIR" 2>/dev/null || true)"
  compact_ent="$(print -r -- "$entitlements" | /usr/bin/tr -d ' \t\n')"

  if print -r -- "$compact_ent" | /usr/bin/grep -q '<key>get-task-allow</key><true/>'; then
    echo "⚠️  get-task-allow = true（个人/开发证书）：CardSe 已在 Release 二进制内置 P_TRACED 调试监控予以缓解，若有条件仍建议优先用 Ad Hoc 描述文件签名。"
    warned=1
  else
    echo "✅ 未开启 get-task-allow"
  fi

  if print -r -- "$compact_ent" | /usr/bin/grep -Eq 'icloud|ubiquity|aps-environment'; then
    echo "❌ 签名描述文件注入了 iCloud 或远程推送权限（违反零同步原则）"
    failed=1
  else
    echo "✅ 无 iCloud / Ubiquity / 推送同步权限"
  fi
else
  echo "⚠️  当前 IPA 尚未完成有效代码签名（若检查的是未签名包属正常现象）"
  warned=1
fi

echo
if [[ $failed -ne 0 ]]; then
  echo "结论：❌ 安全检查未通过，严禁安装此 IPA！"
  exit 1
elif [[ $warned -ne 0 ]]; then
  echo "结论：⚠️ 未发现恶意注入或篡改，但存在提示项（详见上方说明）。"
else
  echo "结论：✅ 全部最高安全检查项通过"
fi
