<?php

	/**
	 * action components for the cosign_authentication module
	 */
	class auth_cosignActionComponents extends TBGActionComponent
	{
		public function componentSettings()
		{
			if (!extension_loaded('cosign'))
			{
				$this->nocosign = true;
			}
			else
			{
				$this->nocosign = false;
			}
		}
	}

