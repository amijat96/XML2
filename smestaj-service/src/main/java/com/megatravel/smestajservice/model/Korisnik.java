package com.megatravel.smestajservice.model;

import java.util.Date;

public class Korisnik {
	
    private long idKorisnik;
    private String email;
    private String ime;
    private String prezime;
    private String lozinka;
    private Date datumClanstva;
    private boolean registrovan;
    private String rola;

    /**
     * Gets the value of the idKorisnik property.
     * 
     */
    public long getIdKorisnik() {
        return idKorisnik;
    }

    /**
     * Sets the value of the idKorisnik property.
     * 
     */
    public void setIdKorisnik(long value) {
        this.idKorisnik = value;
    }

    /**
     * Gets the value of the email property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEmail() {
        return email;
    }

    /**
     * Sets the value of the email property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEmail(String value) {
        this.email = value;
    }

    /**
     * Gets the value of the ime property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getIme() {
        return ime;
    }

    /**
     * Sets the value of the ime property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setIme(String value) {
        this.ime = value;
    }

    /**
     * Gets the value of the prezime property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPrezime() {
        return prezime;
    }

    /**
     * Sets the value of the prezime property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPrezime(String value) {
        this.prezime = value;
    }

    /**
     * Gets the value of the lozinka property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLozinka() {
        return lozinka;
    }

    /**
     * Sets the value of the lozinka property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLozinka(String value) {
        this.lozinka = value;
    }

    /**
     * Gets the value of the datumClanstva property.
     * 
     * @return
     *     possible object is
     *     {@link Date }
     *     
     */
    public Date getDatumClanstva() {
        return datumClanstva;
    }

    /**
     * Sets the value of the datumClanstva property.
     * 
     * @param value
     *     allowed object is
     *     {@link Date }
     *     
     */
    public void setDatumClanstva(Date value) {
        this.datumClanstva = value;
    }

    /**
     * Gets the value of the registrovan property.
     * 
     */
    public boolean isRegistrovan() {
        return registrovan;
    }

    /**
     * Sets the value of the registrovan property.
     * 
     */
    public void setRegistrovan(boolean value) {
        this.registrovan = value;
    }

	public String getRola() {
		return rola;
	}

	public void setRola(String rola) {
		this.rola = rola;
	}

    /**
     * Gets the value of the listaRezervacija property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the listaRezervacija property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getListaRezervacija().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Long }
     * 
     * 
     */
    
    
    
    /*public List<Long> getListaRezervacija() {
        if (listaRezervacija == null) {
            listaRezervacija = new ArrayList<Long>();
        }
        return this.listaRezervacija;
    }*/

}
