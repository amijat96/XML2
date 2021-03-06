package com.megatravel.agentlocalbackend.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.megatravel.agentlocalbackend.model.SamostalnaRezervacija;
import com.megatravel.agentlocalbackend.model.Smestaj;
import com.megatravel.agentlocalbackend.repository.SamostalnaRezervacijaRepository;
import com.megatravel.agentlocalbackend.repository.SmestajRepository;

@Component
public class SamostalnaRezervacijaService {

	@Autowired
	private SamostalnaRezervacijaRepository rezervacijaRepository;

	@Autowired
	private SmestajRepository smestajRepository;
	
	public SamostalnaRezervacija save(SamostalnaRezervacija s) {
		return rezervacijaRepository.save(s);
	}

	public SamostalnaRezervacija findOne(Long idRezervacije, Long idAgenta) {
		SamostalnaRezervacija rez = rezervacijaRepository.getOne(idRezervacije);
		if (rez!=null) {
			Smestaj smestaj = smestajRepository.getOne(rez.getSmestajId());
			if (smestaj!=null) {
				if (smestaj.getVlasnik()==idAgenta) {
					return rez;
				}
			}
		}
		return null;
	}

	public void remove(Long id) {
		rezervacijaRepository.deleteById(id);
	}
	
	
}
