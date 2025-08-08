// auth.js - 用户认证管理
class AuthManager {
    constructor() {
        this.currentUser = null;
        this.sessionToken = null;
        this.init();
    }
    
    async init() {
        // 从localStorage获取会话token
        this.sessionToken = localStorage.getItem('session_token');
        
        // 如果有token，验证并获取用户信息
        if (this.sessionToken) {
            await this.getCurrentUser();
        }
    }
    
    // ==================== 用户注册 ====================
    async register(username, email, password) {
        try {
            // 确保配置已加载
            if (!window.configManager.isLoaded) {
                await window.configManager.loadConfig();
            }
            
            const response = await fetch(window.configManager.getFullApiUrl('/api/auth/register'), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    email: email,
                    password: password
                })
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.detail || '注册失败');
            }
            
            return result;
            
        } catch (error) {
            console.error('❌ 注册失败:', error);
            return {
                success: false,
                message: error.message || '注册失败，请稍后重试'
            };
        }
    }
    
    // ==================== 用户登录 ====================
    async login(username, password) {
        try {
            // 确保配置已加载
            if (!window.configManager.isLoaded) {
                await window.configManager.loadConfig();
            }
            
            const response = await fetch(window.configManager.getFullApiUrl('/api/auth/login'), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.detail || '登录失败');
            }
            
            if (result.success && result.session_token) {
                // 保存会话信息
                this.sessionToken = result.session_token;
                this.currentUser = result.user;
                
                // 保存到localStorage
                localStorage.setItem('session_token', this.sessionToken);
                localStorage.setItem('current_user', JSON.stringify(this.currentUser));
                
                console.log('✅ 登录成功:', this.currentUser);
            }
            
            return result;
            
        } catch (error) {
            console.error('❌ 登录失败:', error);
            return {
                success: false,
                message: error.message || '登录失败，请稍后重试'
            };
        }
    }
    
    // ==================== 用户登出 ====================
    async logout() {
        try {
            if (this.sessionToken) {
                // 确保配置已加载
                if (!window.configManager.isLoaded) {
                    await window.configManager.loadConfig();
                }
                
                // 调用后端登出API
                await fetch(window.configManager.getFullApiUrl('/api/auth/logout'), {
                    method: 'POST',
                    headers: {
                        'Cookie': `session_token=${this.sessionToken}`
                    }
                });
            }
            
        } catch (error) {
            console.error('❌ 登出请求失败:', error);
        } finally {
            // 清除本地存储
            this.sessionToken = null;
            this.currentUser = null;
            localStorage.removeItem('session_token');
            localStorage.removeItem('current_user');
            
            console.log('✅ 已登出');
        }
    }
    
    // ==================== 获取当前用户信息 ====================
    async getCurrentUser() {
        try {
            if (!this.sessionToken) {
                return null;
            }
            
            // 确保配置已加载
            if (!window.configManager.isLoaded) {
                await window.configManager.loadConfig();
            }
            
            const response = await fetch(window.configManager.getFullApiUrl('/api/auth/me'), {
                method: 'GET',
                headers: {
                    'Cookie': `session_token=${this.sessionToken}`
                }
            });
            
            if (!response.ok) {
                // 会话无效，清除本地存储
                this.logout();
                return null;
            }
            
            const result = await response.json();
            
            if (result.success && result.user) {
                this.currentUser = result.user;
                localStorage.setItem('current_user', JSON.stringify(this.currentUser));
                return this.currentUser;
            }
            
            return null;
            
        } catch (error) {
            console.error('❌ 获取用户信息失败:', error);
            return null;
        }
    }
    
    // ==================== 检查登录状态 ====================
    async checkLoginStatus() {
        const user = await this.getCurrentUser();
        return user !== null;
    }
    
    // ==================== 获取用户信息 ====================
    getUser() {
        return this.currentUser;
    }
    
    // ==================== 检查是否已登录 ====================
    isLoggedIn() {
        return this.currentUser !== null && this.sessionToken !== null;
    }
    
    // ==================== 获取会话Token ====================
    getSessionToken() {
        return this.sessionToken;
    }
    
    // ==================== 显示错误信息 ====================
    showError(message) {
        const errorElement = document.getElementById('errorMessage');
        const successElement = document.getElementById('successMessage');
        
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
        }
        
        if (successElement) {
            successElement.style.display = 'none';
        }
        
        // 3秒后自动隐藏
        setTimeout(() => {
            if (errorElement) {
                errorElement.style.display = 'none';
            }
        }, 5000);
    }
    
    // ==================== 显示成功信息 ====================
    showSuccess(message) {
        const errorElement = document.getElementById('errorMessage');
        const successElement = document.getElementById('successMessage');
        
        if (successElement) {
            successElement.textContent = message;
            successElement.style.display = 'block';
        }
        
        if (errorElement) {
            errorElement.style.display = 'none';
        }
        
        // 5秒后自动隐藏
        setTimeout(() => {
            if (successElement) {
                successElement.style.display = 'none';
            }
        }, 5000);
    }
    
    // ==================== 密码强度检查 ====================
    checkPasswordStrength(password) {
        let strength = 0;
        const checks = {
            length: password.length >= 8,
            lowercase: /[a-z]/.test(password),
            uppercase: /[A-Z]/.test(password),
            numbers: /\d/.test(password),
            symbols: /[^\w\s]/.test(password)
        };
        
        strength = Object.values(checks).filter(Boolean).length;
        
        if (strength < 3) return 'weak';
        if (strength < 5) return 'medium';
        return 'strong';
    }
    
    // ==================== 更新密码强度指示器 ====================
    updatePasswordStrength(password, strengthElement) {
        if (!strengthElement) return;
        
        const strength = this.checkPasswordStrength(password);
        const bar = strengthElement.querySelector('.password-strength-bar');
        
        if (bar) {
            bar.className = 'password-strength-bar';
            if (password.length > 0) {
                bar.classList.add(`password-strength-${strength}`);
            }
        }
    }
    
    // ==================== 创建用户头像 ====================
    createUserAvatar(username) {
        const firstLetter = username.charAt(0).toUpperCase();
        return `<div class="user-avatar">${firstLetter}</div>`;
    }
    
    // ==================== 格式化用户显示名 ====================
    formatUserDisplayName(user) {
        return user.username || user.email || '未知用户';
    }
}

// ==================== 全局认证管理器实例 ====================
window.authManager = new AuthManager();

// ==================== 页面加载完成后的通用处理 ====================
document.addEventListener('DOMContentLoaded', function() {
    // 为所有登出按钮添加事件监听
    document.querySelectorAll('.logout-btn').forEach(btn => {
        btn.addEventListener('click', async function(e) {
            e.preventDefault();
            
            if (confirm('确定要登出吗？')) {
                await window.authManager.logout();
                window.location.href = 'login.html';
            }
        });
    });
});

// ==================== 工具函数 ====================

// 验证邮箱格式
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// 验证用户名格式
function validateUsername(username) {
    // 用户名只能包含字母、数字、下划线，3-20个字符
    const re = /^[a-zA-Z0-9_]{3,20}$/;
    return re.test(username);
}

// 防抖函数
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}