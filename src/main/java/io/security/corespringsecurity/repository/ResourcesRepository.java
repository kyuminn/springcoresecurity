package io.security.corespringsecurity.repository;

import io.security.corespringsecurity.domain.entity.Resources;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

// ImportBeanDefinitionRegistor 인터페이스가 JpaReposiotry를 상속받는 모든 인터페이스를 bean으로 등록해줌
public interface ResourcesRepository extends JpaRepository<Resources, Long> {

    @Query("select r from Resources r join fetch r.roleSet where r.resourceType = 'url' order by r.orderNum desc")
    List<Resources> findAllResources();
}