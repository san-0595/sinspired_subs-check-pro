package parse

import (
	"github.com/sinspired/subs-check-pro/utils"
	"net/url"
	"strings"
)

// NormalizeGitHubRawURL 将 GitHub 的 blob 或 raw 页面链接转换为 raw.githubusercontent.com 直链
func NormalizeGitHubRawURL(urlStr string) string {
	// 如果不是 github.com 的链接，或者已经是 raw.githubusercontent.com，直接返回
	if !strings.Contains(urlStr, "github.com") || strings.Contains(urlStr, "raw.githubusercontent.com") {
		return urlStr
	}

	// 移除可能存在的 www. 前缀，统一处理
	urlStr = strings.Replace(urlStr, "www.github.com", "github.com", 1)

	// 检查是否包含 /blob/ 或 /raw/
	// GitHub 结构通常是: github.com/{user}/{repo}/[blob|raw]/{branch}/{path}
	// 目标结构是: raw.githubusercontent.com/{user}/{repo}/{branch}/{path}

	if strings.Contains(urlStr, "/blob/") {
		urlStr = strings.Replace(urlStr, "github.com", "raw.githubusercontent.com", 1)
		urlStr = strings.Replace(urlStr, "/blob/", "/", 1)
	} else if strings.Contains(urlStr, "/raw/") {
		urlStr = strings.Replace(urlStr, "github.com", "raw.githubusercontent.com", 1)
		urlStr = strings.Replace(urlStr, "/raw/", "/", 1)
	}

	return urlStr
}

func SsLocalRequest(u *url.URL) bool {
	return utils.IsLocalURL(u.Hostname()) &&
		(strings.Contains(u.Fragment, "Keep") || strings.Contains(u.Path, "history") || strings.Contains(u.Path, "all"))
}

func EnsureScheme(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		return s
	}

	if strings.HasPrefix(s, "127.0.0.1") || strings.HasPrefix(s, "localhost") {
		return "http://" + s
	}

	// Github 默认 HTTPS
	if strings.HasPrefix(s, "raw.githubusercontent.com/") || strings.HasPrefix(s, "github.com/") {
		return "https://" + s
	}

	// 本地环境默认 HTTP
	if utils.IsLocalURL(strings.Split(s, ":")[0]) {
		return "http://" + s
	}

	return "http://" + s
}

// CleanURL 清洗 URL，移除首尾空白及尾部常见的误复制标点符号
func CleanURL(raw string) string {
	// 1. 去除首尾的标准空白符 (空格, 换行, Tab)
	s := strings.TrimSpace(raw)

	// 2. 定义尾部需要剔除的“垃圾字符”集合
	// "  : 双引号
	// '  : 单引号
	// `  : 反引号 (Markdown常用)
	// ,  : 逗号
	// ;  : 分号
	// .  : 句号 (虽然URL允许结尾有点，但在订阅链接场景下通常是句尾误复制)
	// )  : 右括号 (Markdown链接常用)
	// ]  : 右方括号
	// }  : 右大括号
	// >  : 大于号 (Email/引用常用)
	cutset := "\"'`,;.)]}>"

	// 3. 循环移除尾部所有属于 cutset 的字符，直到遇到非 cutset 字符为止
	return strings.TrimRight(s, cutset)
}
