/**
 * Access Control
 *
 * Module for role-based access control (RBAC)
 */

//// Core modules

//// External modules
const lodash = require('lodash')

//// Modules


/**
 * Get role-level permissions merged with user-level permissions.
 * @param {Object} user
 * @param {Array} allRoles Array of role objects
 * @param {Function} filter Callback function to filter the merged permissions before returning.
 * @returns {Array} 1D array of permissions.
 */
const getUserPermissions = (user, allRoles, filter) => {

    let finalPermissions = []
    let userRoles = lodash.get(user, 'roles', [])

    // Loop all user's roles
    // We merge all permissions from all the user's roles into finalPermission
    lodash.each(userRoles, (userRoleKey) => {

        // Find role from all roles
        let foundRole = lodash.find(allRoles, o => o.key === userRoleKey) // Find from ACL roles list

        // Get permissions list from role
        let rolePermissions = lodash.get(foundRole, 'permissions', [])

        finalPermissions = finalPermissions.concat(rolePermissions)

    })

    let userPermission = lodash.get(user, 'permissions', [])
    finalPermissions = finalPermissions.concat(userPermission)

    if(filter !== undefined){
        return filter(finalPermissions)
    }
    return finalPermissions
}

/**
 * All permissionKeys must match
 * @param {Object} user
 * @param {Array} permissionKeys
 * @param {Array} allRoles Array of roles
 * @returns {Boolean}
 */
const and = (user, permissionKeys, allRoles) => {

    let permissions = getUserPermissions(user, allRoles)

    // console.log(`all of ${permissionKeys}`, permissions)

    return lodash.difference(permissionKeys, permissions).length <= 0 ? true : false

}

/**
 * Check if user can do something
 * @param {Object} user
 * @param {Array} permissionKey Denotes something
 * @param {Array} allRoles Array of roles
 * @returns {Boolean}
 */
const can = (user, permissionKey, allRoles) => {

    let permissions = getUserPermissions(user, allRoles)

    // console.log(`user can ${permissionKey}`, permissions)

    return permissions.includes(permissionKey)
}

/**
 * At least one permissionKeys must match
 * @param {Object} user
 * @param {Array} permissionKeys
 * @param {Array} allRoles Array of roles
 * @returns {Boolean}
 */
const or = (user, permissionKeys, allRoles) => {

    let permissions = getUserPermissions(user, allRoles)

    // console.log(`at least one ${permissionKeys}`, permissions)

    return lodash.intersection(permissionKeys, permissions).length > 0 ? true : false

}





module.exports = {
    and: and,
    can: can,
    getUserPermissions: getUserPermissions,
    or: or,
}