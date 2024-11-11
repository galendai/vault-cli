from typing import Dict, List
from datetime import datetime

class PasswordStore:
    # ... existing code ...

    def get_password(self, site: str) -> Dict:
        """
        获取指定站点的密码条目
        
        Args:
            site: 站点名称
            
        Returns:
            包含密码条目信息的字典，如果不存在则返回 None
        """
        return self.passwords.get(site)

    def list_sites(self) -> List[str]:
        """
        列出所有站点
        
        Returns:
            站点名称列表
        """
        return list(self.passwords.keys())

    def search_by_tags(self, tags: List[str]) -> List[str]:
        """
        按标签搜索密码条目
        
        Args:
            tags: 标签列表
            
        Returns:
            匹配标签的站点名称列表
        """
        if not tags:
            return self.list_sites()
            
        matching_sites = []
        for site, data in self.passwords.items():
            if any(tag in data.get('tags', []) for tag in tags):
                matching_sites.append(site)
        return matching_sites

    def update_password(self, site: str, encrypted_password: str = None,
                       url: str = None, tags: List[str] = None, notes: str = None):
        """
        更新密码条目
        
        Args:
            site: 站点名称
            encrypted_password: 加密后的新密码（可选）
            url: 新的URL（可选）
            tags: 新的标签列表（可选）
            notes: 新的备注（可选）
        """
        if site not in self.passwords:
            raise KeyError(f"No password entry found for {site}")
            
        if encrypted_password:
            self.passwords[site]['password'] = encrypted_password
        if url is not None:
            self.passwords[site]['url'] = url
        if tags is not None:
            self.passwords[site]['tags'] = tags
        if notes is not None:
            self.passwords[site]['notes'] = notes
            
        self.passwords[site]['modified_at'] = datetime.now().isoformat()
        self._save_passwords() 