//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.5.1 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.04.22 at 11:00:08 PM CEST 
//


package io.xws.adminservice.model;

import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "idKorisnik",
    "email",
    "ime",
    "prezime",
    "lozinka",
    "datumClanstva",
    "registrovan",
    "listaRezervacija"
})
@XmlRootElement(name = "Korisnik")
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Korisnik {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
    protected long idKorisnik;
    @XmlElement(required = true)
    protected String email;
    @XmlElement(required = true)
    protected String ime;
    @XmlElement(required = true)
    protected String prezime;
    @XmlElement(required = true)
    protected String lozinka;
    @XmlElement(required = true)
    @XmlSchemaType(name = "date")
    protected Date datumClanstva;
    @XmlElement(defaultValue = "false")
    protected boolean registrovan;
    protected boolean blokiran;
    protected boolean aktiviran;
//    @XmlList
//    @XmlElement(type = Long.class)
//    protected List<Long> listaRezervacija;

}
