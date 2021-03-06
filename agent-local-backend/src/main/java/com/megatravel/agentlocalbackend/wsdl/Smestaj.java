//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.11 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.06.12 at 12:36:07 PM CEST 
//


package com.megatravel.agentlocalbackend.wsdl;

import java.math.BigDecimal;
import java.util.Set;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import com.megatravel.agentlocalbackend.model.TImage;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="idSmestaja" type="{http://www.w3.org/2001/XMLSchema}long"/&gt;
 *         &lt;element name="adresa" type="{https://megatravel.com}TAdresa"/&gt;
 *         &lt;element name="latitude" type="{http://www.w3.org/2001/XMLSchema}decimal"/&gt;
 *         &lt;element name="longitude" type="{http://www.w3.org/2001/XMLSchema}decimal"/&gt;
 *         &lt;element name="tipSmestaja" type="{https://megatravel.com}TipSmestaja"/&gt;
 *         &lt;element name="kategorijaSmestaja" type="{https://megatravel.com}KategorijaSmestaja"/&gt;
 *         &lt;element name="opis" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="maxOsoba" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *         &lt;element name="maxDanaZaOtkazivanje" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *         &lt;element name="cenaProlece" type="{http://www.w3.org/2001/XMLSchema}float"/&gt;
 *         &lt;element name="cenaLeto" type="{http://www.w3.org/2001/XMLSchema}float"/&gt;
 *         &lt;element name="cenaJesen" type="{http://www.w3.org/2001/XMLSchema}float"/&gt;
 *         &lt;element name="cenaZima" type="{http://www.w3.org/2001/XMLSchema}float"/&gt;
 *         &lt;element name="vlasnik" type="{http://www.w3.org/2001/XMLSchema}long" minOccurs="0"/&gt;
 *         &lt;element name="listaDodatnihUsluga" type="{https://megatravel.com}DodatneUsluge" maxOccurs="unbounded"/&gt;
 *         &lt;element name="listaSlika" maxOccurs="unbounded"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="idImage" type="{http://www.w3.org/2001/XMLSchema}long"/&gt;
 *                   &lt;element name="smestaj" type="{http://www.w3.org/2001/XMLSchema}anyType" minOccurs="0"/&gt;
 *                   &lt;element name="name" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *                   &lt;element name="bytes" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "idSmestaja",
    "adresa",
    "latitude",
    "longitude",
    "tipSmestaja",
    "kategorijaSmestaja",
    "opis",
    "maxOsoba",
    "maxDanaZaOtkazivanje",
    "cenaProlece",
    "cenaLeto",
    "cenaJesen",
    "cenaZima",
    "vlasnik",
    "listaDodatnihUsluga",
    "listaSlika"
})
@XmlRootElement(name = "Smestaj")
public class Smestaj {

    protected long idSmestaja;
    @XmlElement(required = true)
    protected TAdresa adresa;
    @XmlElement(required = true)
    protected BigDecimal latitude;
    @XmlElement(required = true)
    protected BigDecimal longitude;
    @XmlElement(required = true)
    protected TipSmestaja tipSmestaja;
    @XmlElement(required = true)
    protected KategorijaSmestaja kategorijaSmestaja;
    @XmlElement(required = true)
    protected String opis;
    protected int maxOsoba;
    protected int maxDanaZaOtkazivanje;
    protected float cenaProlece;
    protected float cenaLeto;
    protected float cenaJesen;
    protected float cenaZima;
    protected Long vlasnik;
    @XmlElement(required = true)
    protected Set<DodatneUsluge> listaDodatnihUsluga;
    @XmlElement(required = true)
    protected Set<TImage> listaSlika;

    /**
     * Gets the value of the idSmestaja property.
     * 
     */
    public long getIdSmestaja() {
        return idSmestaja;
    }

    /**
     * Sets the value of the idSmestaja property.
     * 
     */
    public void setIdSmestaja(long value) {
        this.idSmestaja = value;
    }

    /**
     * Gets the value of the adresa property.
     * 
     * @return
     *     possible object is
     *     {@link TAdresa }
     *     
     */
    public TAdresa getAdresa() {
        return adresa;
    }

    /**
     * Sets the value of the adresa property.
     * 
     * @param value
     *     allowed object is
     *     {@link TAdresa }
     *     
     */
    public void setAdresa(TAdresa value) {
        this.adresa = value;
    }

    /**
     * Gets the value of the latitude property.
     * 
     * @return
     *     possible object is
     *     {@link BigDecimal }
     *     
     */
    public BigDecimal getLatitude() {
        return latitude;
    }

    /**
     * Sets the value of the latitude property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigDecimal }
     *     
     */
    public void setLatitude(BigDecimal value) {
        this.latitude = value;
    }

    /**
     * Gets the value of the longitude property.
     * 
     * @return
     *     possible object is
     *     {@link BigDecimal }
     *     
     */
    public BigDecimal getLongitude() {
        return longitude;
    }

    /**
     * Sets the value of the longitude property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigDecimal }
     *     
     */
    public void setLongitude(BigDecimal value) {
        this.longitude = value;
    }

    /**
     * Gets the value of the tipSmestaja property.
     * 
     * @return
     *     possible object is
     *     {@link TipSmestaja }
     *     
     */
    public TipSmestaja getTipSmestaja() {
        return tipSmestaja;
    }

    /**
     * Sets the value of the tipSmestaja property.
     * 
     * @param value
     *     allowed object is
     *     {@link TipSmestaja }
     *     
     */
    public void setTipSmestaja(TipSmestaja value) {
        this.tipSmestaja = value;
    }

    /**
     * Gets the value of the kategorijaSmestaja property.
     * 
     * @return
     *     possible object is
     *     {@link KategorijaSmestaja }
     *     
     */
    public KategorijaSmestaja getKategorijaSmestaja() {
        return kategorijaSmestaja;
    }

    /**
     * Sets the value of the kategorijaSmestaja property.
     * 
     * @param value
     *     allowed object is
     *     {@link KategorijaSmestaja }
     *     
     */
    public void setKategorijaSmestaja(KategorijaSmestaja value) {
        this.kategorijaSmestaja = value;
    }

    /**
     * Gets the value of the opis property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getOpis() {
        return opis;
    }

    /**
     * Sets the value of the opis property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOpis(String value) {
        this.opis = value;
    }

    /**
     * Gets the value of the maxOsoba property.
     * 
     */
    public int getMaxOsoba() {
        return maxOsoba;
    }

    /**
     * Sets the value of the maxOsoba property.
     * 
     */
    public void setMaxOsoba(int value) {
        this.maxOsoba = value;
    }

    /**
     * Gets the value of the maxDanaZaOtkazivanje property.
     * 
     */
    public int getMaxDanaZaOtkazivanje() {
        return maxDanaZaOtkazivanje;
    }

    /**
     * Sets the value of the maxDanaZaOtkazivanje property.
     * 
     */
    public void setMaxDanaZaOtkazivanje(int value) {
        this.maxDanaZaOtkazivanje = value;
    }

    /**
     * Gets the value of the cenaProlece property.
     * 
     */
    public float getCenaProlece() {
        return cenaProlece;
    }

    /**
     * Sets the value of the cenaProlece property.
     * 
     */
    public void setCenaProlece(float value) {
        this.cenaProlece = value;
    }

    /**
     * Gets the value of the cenaLeto property.
     * 
     */
    public float getCenaLeto() {
        return cenaLeto;
    }

    /**
     * Sets the value of the cenaLeto property.
     * 
     */
    public void setCenaLeto(float value) {
        this.cenaLeto = value;
    }

    /**
     * Gets the value of the cenaJesen property.
     * 
     */
    public float getCenaJesen() {
        return cenaJesen;
    }

    /**
     * Sets the value of the cenaJesen property.
     * 
     */
    public void setCenaJesen(float value) {
        this.cenaJesen = value;
    }

    /**
     * Gets the value of the cenaZima property.
     * 
     */
    public float getCenaZima() {
        return cenaZima;
    }

    /**
     * Sets the value of the cenaZima property.
     * 
     */
    public void setCenaZima(float value) {
        this.cenaZima = value;
    }

    /**
     * Gets the value of the vlasnik property.
     * 
     * @return
     *     possible object is
     *     {@link Long }
     *     
     */
    public Long getVlasnik() {
        return vlasnik;
    }

    /**
     * Sets the value of the vlasnik property.
     * 
     * @param value
     *     allowed object is
     *     {@link Long }
     *     
     */
    public void setVlasnik(Long value) {
        this.vlasnik = value;
    }

    public Set<DodatneUsluge> getListaDodatnihUsluga() {
		return listaDodatnihUsluga;
	}

	public void setListaDodatnihUsluga(Set<DodatneUsluge> listaDodatnihUsluga) {
		this.listaDodatnihUsluga = listaDodatnihUsluga;
	}

	public Set<TImage> getListaSlika() {
		return listaSlika;
	}

	public void setListaSlika(Set<TImage> listaSlika) {
		this.listaSlika = listaSlika;
	}



	/**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType&gt;
     *   &lt;complexContent&gt;
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *       &lt;sequence&gt;
     *         &lt;element name="idImage" type="{http://www.w3.org/2001/XMLSchema}long"/&gt;
     *         &lt;element name="smestaj" type="{http://www.w3.org/2001/XMLSchema}anyType" minOccurs="0"/&gt;
     *         &lt;element name="name" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
     *         &lt;element name="bytes" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/&gt;
     *       &lt;/sequence&gt;
     *     &lt;/restriction&gt;
     *   &lt;/complexContent&gt;
     * &lt;/complexType&gt;
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "idImage",
        "smestaj",
        "name",
        "bytes"
    })
    public static class ListaSlika {

        protected long idImage;
        protected Object smestaj;
        @XmlElement(required = true)
        protected String name;
        @XmlElement(required = true)
        protected byte[] bytes;

        /**
         * Gets the value of the idImage property.
         * 
         */
        public long getIdImage() {
            return idImage;
        }

        /**
         * Sets the value of the idImage property.
         * 
         */
        public void setIdImage(long value) {
            this.idImage = value;
        }

        /**
         * Gets the value of the smestaj property.
         * 
         * @return
         *     possible object is
         *     {@link Object }
         *     
         */
        public Object getSmestaj() {
            return smestaj;
        }

        /**
         * Sets the value of the smestaj property.
         * 
         * @param value
         *     allowed object is
         *     {@link Object }
         *     
         */
        public void setSmestaj(Object value) {
            this.smestaj = value;
        }

        /**
         * Gets the value of the name property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getName() {
            return name;
        }

        /**
         * Sets the value of the name property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setName(String value) {
            this.name = value;
        }

        /**
         * Gets the value of the bytes property.
         * 
         * @return
         *     possible object is
         *     byte[]
         */
        public byte[] getBytes() {
            return bytes;
        }

        /**
         * Sets the value of the bytes property.
         * 
         * @param value
         *     allowed object is
         *     byte[]
         */
        public void setBytes(byte[] value) {
            this.bytes = value;
        }

    }

}
