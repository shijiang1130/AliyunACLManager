mvn package

java -jar target\aliyun-acl-manager-2.0-SNAPSHOT-jar-with-dependencies.jar

----------------------------------
源IP: xxx.xxx.xxx.xxx
协议: TCP
端口范围: 22/22
策略: Drop
优先级: 1
----------------------------------

=== 被阻止IP统计 ===
共有 0 个IP被阻止:
===================

=== 使用方法 ===
1. 添加阻止规则: java AliyunAclManager <IP地址>
   示例: java AliyunAclManager 192.168.1.100
2. 添加白名单规则: java AliyunAclManager whitelist <IP地址>
   示例: java AliyunAclManager whitelist 192.168.1.100
3. 删除IP规则: java AliyunAclManager remove <IP地址>
   示例: java AliyunAclManager remove 192.168.1.100
4. 绑定实例: java AliyunAclManager <实例ID>
   示例: java AliyunAclManager i-xxxxxxxxxxxxxxxxxx
5. 查询指定安全组: java AliyunAclManager <安全组ID>
   示例: java AliyunAclManager sg-xxxxxxxxxxxxxxxxxx
6. 查询默认安全组: java AliyunAclManager
==================
