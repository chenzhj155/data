#pragma once

// 包含所有 Hook 模块
#include "FileHooks.h"
#include "RegistryHooks.h"
#include "MemoryHooks.h"
#include "ProcessHooks.h"
#include "ThreadHooks.h"
#include "NetworkHooks.h"
#include "SyncHooks.h"
#include "CryptoHooks.h"
#include "InjectionHooks.h"
#include "AntiDebugHooks.h"
#include "SystemInfoHooks.h"

// ============================================
// 统一安装所有 Hook
// ============================================
void InstallAllApiHooks();