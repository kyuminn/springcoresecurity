package io.security.corespringsecurity.domain.entity;

import lombok.*;

import javax.persistence.*;

@Entity
@Table(name="ACCESS_IP")
@Getter
@Setter
@EqualsAndHashCode(of="id")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessIP {

    @Id
    @GeneratedValue
    @Column(name="IP_ID",unique = true, nullable = false)
    private Long id;

    @Column(name="IP_ADDRESS", nullable = false)
    private String ipAddress;


}
