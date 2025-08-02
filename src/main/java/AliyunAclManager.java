import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.ecs.model.v20140526.*;
import java.util.List;
import java.util.regex.Pattern;

public class AliyunAclManager {

    private static final String CONFIG_FILE = "aliyun.properties";
    private static final String ACCESS_KEY_ID;
    private static final String ACCESS_KEY_SECRET;
    private static final String REGION_ID;
    private static final String DEFAULT_GROUP_NAME = "sg-devops";
    private static final Pattern IP_PATTERN = Pattern.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    static {
        java.util.Properties props = new java.util.Properties();
        try (java.io.InputStream input = AliyunAclManager.class.getClassLoader().getResourceAsStream(CONFIG_FILE)) {
            if (input == null) {
                throw new RuntimeException("找不到配置文件: " + CONFIG_FILE);
            }
            props.load(input);
            ACCESS_KEY_ID = props.getProperty("accessKeyId");
            ACCESS_KEY_SECRET = props.getProperty("accessKeySecret");
            REGION_ID = props.getProperty("regionId");
            if (ACCESS_KEY_ID == null || ACCESS_KEY_SECRET == null || REGION_ID == null) {
                throw new RuntimeException("配置文件缺少必要的阿里云参数: accessKeyId, accessKeySecret, regionId");
            }
        } catch (Exception e) {
            throw new RuntimeException("无法加载配置文件: " + CONFIG_FILE, e);
        }
    }

    private static IAcsClient createClient() throws ClientException {
        DefaultProfile profile = DefaultProfile.getProfile(REGION_ID, ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        return new DefaultAcsClient(profile);
    }

    private static String getOrCreateDefaultGroup() throws ClientException {
        IAcsClient client = createClient();
        
        // First try to find existing group
        DescribeSecurityGroupsRequest describeRequest = new DescribeSecurityGroupsRequest();
        describeRequest.setSecurityGroupName(DEFAULT_GROUP_NAME);
        DescribeSecurityGroupsResponse describeResponse = client.getAcsResponse(describeRequest);
        
        if (!describeResponse.getSecurityGroups().isEmpty()) {
            return describeResponse.getSecurityGroups().get(0).getSecurityGroupId();
        }
        
        // Create new group if not exists
        CreateSecurityGroupRequest createRequest = new CreateSecurityGroupRequest();
        createRequest.setSecurityGroupName(DEFAULT_GROUP_NAME);
        createRequest.setDescription("Default security group for devops");
        CreateSecurityGroupResponse createResponse = client.getAcsResponse(createRequest);
        
        return createResponse.getSecurityGroupId();
    }

    private static void addBlockRule(String securityGroupId, String ipAddress) throws ClientException {
        IAcsClient client = createClient();
        int[] ports = {22, 80, 443};
        
        for (int port : ports) {
            AuthorizeSecurityGroupRequest request = new AuthorizeSecurityGroupRequest();
            request.setSecurityGroupId(securityGroupId);
            request.setIpProtocol("tcp");
            request.setPortRange(String.valueOf(port) + "/" + String.valueOf(port));
            request.setSourceCidrIp(ipAddress);
            request.setPolicy("drop"); // block the traffic
            request.setPriority("1"); // high priority
            request.setDescription("Block rule for " + ipAddress);
            
            client.getAcsResponse(request);
            System.out.println("已添加阻止规则: 端口 " + port + " 来自 " + ipAddress);
        }
    }

    private static void removeRulesForIp(String securityGroupId, String ipAddress) throws ClientException {
        IAcsClient client = createClient();
        
        // First get all ingress rules
        DescribeSecurityGroupAttributeRequest describeRequest = new DescribeSecurityGroupAttributeRequest();
        describeRequest.setSecurityGroupId(securityGroupId);
        describeRequest.setDirection("ingress");
        DescribeSecurityGroupAttributeResponse response = client.getAcsResponse(describeRequest);
        
        List<DescribeSecurityGroupAttributeResponse.Permission> permissions = response.getPermissions();
        if (permissions == null || permissions.isEmpty()) {
            System.out.println("没有找到任何规则需要删除");
            return;
        }

        // Remove all rules matching the IP
        for (DescribeSecurityGroupAttributeResponse.Permission perm : permissions) {
            if (ipAddress.equals(perm.getSourceCidrIp())) {
                RevokeSecurityGroupRequest revokeRequest = new RevokeSecurityGroupRequest();
                revokeRequest.setSecurityGroupId(securityGroupId);
                revokeRequest.setIpProtocol(perm.getIpProtocol());
                revokeRequest.setPortRange(perm.getPortRange());
                revokeRequest.setSourceCidrIp(perm.getSourceCidrIp());
                revokeRequest.setPolicy(perm.getPolicy());
                revokeRequest.setPriority(perm.getPriority());
                
                client.getAcsResponse(revokeRequest);
                System.out.println("已删除规则: " + perm.getIpProtocol() + " " + perm.getPortRange() + " 来自 " + ipAddress);
            }
        }
    }

    private static void bindSecurityGroupToInstance(String instanceId, String securityGroupId) throws ClientException {
        IAcsClient client = createClient();
        JoinSecurityGroupRequest request = new JoinSecurityGroupRequest();
        request.setInstanceId(instanceId);
        request.setSecurityGroupId(securityGroupId);
        client.getAcsResponse(request);
        System.out.println("已绑定安全组 " + securityGroupId + " 到实例 " + instanceId);
    }

    private static void addWhitelistRule(String securityGroupId, String ipAddress) throws ClientException {
        IAcsClient client = createClient();
        int[] ports = {22, 80, 443};
        
        for (int port : ports) {
            AuthorizeSecurityGroupRequest request = new AuthorizeSecurityGroupRequest();
            request.setSecurityGroupId(securityGroupId);
            request.setIpProtocol("tcp");
            request.setPortRange(String.valueOf(port) + "/" + String.valueOf(port));
            request.setSourceCidrIp(ipAddress);
            request.setPolicy("accept"); // allow the traffic
            request.setPriority("1"); // high priority
            request.setDescription("Whitelist rule for " + ipAddress);
            
            client.getAcsResponse(request);
            System.out.println("已添加白名单规则: 端口 " + port + " 来自 " + ipAddress);
        }
    }

    public static void queryIngressRules(String securityGroupId) throws ClientException {
        IAcsClient client = createClient();

        DescribeSecurityGroupAttributeRequest request = new DescribeSecurityGroupAttributeRequest();
        request.setSecurityGroupId(securityGroupId);
        request.setDirection("ingress");
        DescribeSecurityGroupAttributeResponse response = client.getAcsResponse(request);
        
        System.out.println("安全组入方向规则详情：");
        System.out.println("安全组ID: " + securityGroupId);
        System.out.println("----------------------------------");
        
        List<DescribeSecurityGroupAttributeResponse.Permission> permissions = response.getPermissions();
        if (permissions == null || permissions.isEmpty()) {
            System.out.println("没有配置任何入方向规则");
            return;
        }

        java.util.Set<String> blockedIps = new java.util.HashSet<>();
        for (DescribeSecurityGroupAttributeResponse.Permission perm : permissions) {
            System.out.println("源IP: " + perm.getSourceCidrIp());
            System.out.println("协议: " + perm.getIpProtocol());
            System.out.println("端口范围: " + perm.getPortRange());
            System.out.println("策略: " + perm.getPolicy());
            System.out.println("优先级: " + perm.getPriority());
            System.out.println("----------------------------------");
            
            // 收集被阻止的IP
            if ("drop".equals(perm.getPolicy())) {
                blockedIps.add(perm.getSourceCidrIp());
            }
        }
        
        // 输出被阻止IP的统计信息
        System.out.println("\n=== 被阻止IP统计 ===");
        System.out.println("共有 " + blockedIps.size() + " 个IP被阻止:");
        for (String ip : blockedIps) {
            System.out.println("- " + ip);
        }
        System.out.println("===================");
    }

    public static void main(String[] args) {
        try {
            String securityGroupId = getOrCreateDefaultGroup();
            
            if (args.length > 0) {
                if (args[0].equalsIgnoreCase("remove") && args.length > 1 && IP_PATTERN.matcher(args[1]).matches()) {
                    System.out.println("检测到删除命令，正在移除IP " + args[1] + " 的所有规则...");
                    removeRulesForIp(securityGroupId, args[1]);
                } else if (args[0].equalsIgnoreCase("whitelist") && args.length > 1 && IP_PATTERN.matcher(args[1]).matches()) {
                    System.out.println("检测到白名单命令，正在添加白名单规则...");
                    addWhitelistRule(securityGroupId, args[1]);
                } else {
                    String input = args[0];
                    if (IP_PATTERN.matcher(input).matches()) {
                        System.out.println("检测到IP地址参数，正在添加阻止规则...");
                        addBlockRule(securityGroupId, input);
                    } else if (input.startsWith("i-")) {
                        System.out.println("检测到实例ID参数，正在绑定安全组...");
                        bindSecurityGroupToInstance(input, securityGroupId);
                    } else {
                        securityGroupId = input;
                    }
                }
            } else {
                System.out.println("未提供安全组ID，使用默认sg-devops组...");
            }
            
            System.out.println("正在查询安全组入方向规则...");
            queryIngressRules(securityGroupId);
            
            // 如果没有参数，显示使用方法
            if (args.length == 0) {
                System.out.println("\n=== 使用方法 ===");
                System.out.println("1. 添加阻止规则: java AliyunAclManager <IP地址>");
                System.out.println("   示例: java AliyunAclManager 192.168.1.100");
                System.out.println("2. 添加白名单规则: java AliyunAclManager whitelist <IP地址>");
                System.out.println("   示例: java AliyunAclManager whitelist 192.168.1.100");
                System.out.println("3. 删除IP规则: java AliyunAclManager remove <IP地址>");
                System.out.println("   示例: java AliyunAclManager remove 192.168.1.100");
                System.out.println("4. 绑定实例: java AliyunAclManager <实例ID>");
                System.out.println("   示例: java AliyunAclManager i-1234567890abcdef0");
                System.out.println("5. 查询指定安全组: java AliyunAclManager <安全组ID>");
                System.out.println("   示例: java AliyunAclManager sg-1234567890abcdef0");
                System.out.println("6. 查询默认安全组: java AliyunAclManager");
                System.out.println("==================");
            }
        } catch (ClientException e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
