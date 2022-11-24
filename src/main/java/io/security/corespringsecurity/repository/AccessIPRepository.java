package io.security.corespringsecurity.repository;

import io.security.corespringsecurity.domain.entity.AccessIP;
import org.springframework.data.jpa.repository.JpaRepository;


public interface AccessIPRepository extends JpaRepository<AccessIP,Long> {

    AccessIP findByIpAddress(String IpAddress);
}
