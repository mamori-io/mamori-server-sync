const fs = require('fs');

// Read the sync-config.ts file
let content = fs.readFileSync('sync-config.ts', 'utf8');

// Define the sections to wrap with configuration checks
const sections = [
    { name: 'connection_policies_before', start: '//BEFORE CONNECTION POLICIES', end: 'BEFORE CONNECTION POLICIES DONE' },
    { name: 'connection_policies_after', start: '//AFTER CONNECTION POLICIES', end: 'AFTER CONNECTION POLICIES DONE' },
    { name: 'ip_resources', start: '//IP RESOURCES', end: 'IPRESOURCE DONE' },
    { name: 'remote_desktop_logins', start: '//REMOTE DESKTOPS', end: 'REMOTE DESKTOPS DONE' },
    { name: 'http_resources', start: '//HTTP RESOURCE', end: 'HTTP RESOURCES DONE' },
    { name: 'secrets', start: '//SECRETS', end: 'SECRETS DONE' },
    { name: 'ssh_logins', start: '//SSH', end: 'SSH DONE' },
    { name: 'requestable_resources', start: '//REQUESTABLE', end: 'REQUESTABLES DONE' },
    { name: 'roles', start: 'try {\n        let rolesKJ = await io_utils.noThrow(io_role.Role.getAll(api));', end: 'ROLES DONE' },
    { name: 'role_grants', start: 'try {\n        //test API\n        let roleSQL = "select roleid,grantee,withadminoption "', end: 'ROLES GRANTS DONE' },
    { name: 'role_permissions', start: 'try {\n        let rolesKJ = await io_utils.noThrow(io_role.Role.getAll(api));\n        for (let role of rolesKJ) {', end: 'ROLES PERMISSIONS DONE' },
    { name: 'on_demand_policies', start: '//ON DEMAND POLICIES', end: 'ON-DEMAND POLICIES DONE' }
];

// Function to wrap a section with configuration check
function wrapSection(content, sectionName, startPattern, endPattern) {
    const startIndex = content.indexOf(startPattern);
    if (startIndex === -1) return content;
    
    const endIndex = content.indexOf(endPattern, startIndex);
    if (endIndex === -1) return content;
    
    const endIndexWithPattern = endIndex + endPattern.length;
    
    // Find the try block start
    const tryIndex = content.indexOf('try {', startIndex);
    if (tryIndex === -1 || tryIndex > endIndex) return content;
    
    // Find the finally block
    const finallyIndex = content.lastIndexOf('} finally {', endIndex);
    if (finallyIndex === -1) return content;
    
    const beforeSection = content.substring(0, startIndex);
    const sectionStart = content.substring(startIndex, tryIndex);
    const sectionContent = content.substring(tryIndex, finallyIndex);
    const sectionEnd = content.substring(finallyIndex, endIndexWithPattern);
    const afterSection = content.substring(endIndexWithPattern);
    
    const wrappedSection = `${sectionStart}if (shouldSync('${sectionName}')) {
        ${sectionContent}
        } else {
            console.log("${sectionName.toUpperCase().replace(/_/g, ' ')} SKIPPED (disabled in config)");
        }
    `;
    
    return beforeSection + wrappedSection + afterSection;
}

// Apply wrapping to each section
sections.forEach(section => {
    content = wrapSection(content, section.name, section.start, section.end);
});

// Write the updated content back
fs.writeFileSync('sync-config.ts', content);
console.log('Updated sync-config.ts with configuration checks');
