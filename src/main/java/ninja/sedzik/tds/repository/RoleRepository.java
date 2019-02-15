package ninja.sedzik.tds.repository;


import ninja.sedzik.tds.model.Role;
import ninja.sedzik.tds.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleName roleName);
}
